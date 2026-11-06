from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from importlib import metadata
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from pipsutra.models import Dependency, DependencyEdge, Inventory, Package


def _parse_requirement(
    raw: str, *, source: str, group: str = "main"
) -> Dependency | None:
    value = raw.strip()
    if not value or value.startswith("#"):
        return None
    if value.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
        raise ValueError(
            f"Nested requirements and constraints are not supported in v0.1.0: {value}"
        )
    if value.startswith(("-e ", "--editable ")):
        raise ValueError(
            f"Editable/VCS requirements are not supported in v0.1.0: {value}"
        )
    try:
        requirement = Requirement(value)
    except InvalidRequirement as exc:
        raise ValueError(f"Invalid requirement {value!r}: {exc}") from exc

    if requirement.url and requirement.url.startswith(("git+", "hg+", "svn+", "bzr+")):
        raise ValueError(f"VCS requirements are not supported in v0.1.0: {value}")

    active = requirement.marker is None or requirement.marker.evaluate()

    return Dependency(
        name=requirement.name,
        normalized_name=canonicalize_name(requirement.name),
        specifier=str(requirement.specifier),
        source=source,
        group=group,
        marker=str(requirement.marker) if requirement.marker else None,
        active=active,
    )


def discover_requirements(path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        # Strip inline comments only when separated by whitespace.
        content = line.split(" #", maxsplit=1)[0].strip()
        if not content or content.startswith("#"):
            continue
        if content.startswith(
            (
                "--index-url",
                "--extra-index-url",
                "--trusted-host",
                "--find-links",
                "-f ",
                "--no-index",
                "--pre",
                "--only-binary",
                "--no-binary",
                "--require-hashes",
                "--prefer-binary",
                "--no-deps",
            )
        ):
            continue
        content = re.sub(r"\s+--hash(?:=|\s+)\S+", "", content).strip()
        if not content:
            continue
        try:
            dependency = _parse_requirement(
                content, source=f"requirements.txt:{line_number}"
            )
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
        if dependency is not None:
            dependencies.append(dependency)
    return dependencies


def discover_pyproject(path: Path) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    dependencies: list[Dependency] = []

    for raw in project.get("dependencies", []):
        dependency = _parse_requirement(
            raw, source="pyproject.toml:[project].dependencies"
        )
        if dependency:
            dependencies.append(dependency)

    for group, values in project.get("optional-dependencies", {}).items():
        for raw in values:
            dependency = _parse_requirement(
                raw,
                source=f"pyproject.toml:[project].optional-dependencies.{group}",
                group=group,
            )
            if dependency:
                dependencies.append(dependency)

    return dependencies


def discover_declared(project_path: Path) -> tuple[list[Dependency], list[str]]:
    dependencies: list[Dependency] = []
    warnings: list[str] = []

    requirements_file = project_path / "requirements.txt"
    pyproject_file = project_path / "pyproject.toml"

    if requirements_file.is_file():
        dependencies.extend(discover_requirements(requirements_file))
    if pyproject_file.is_file():
        dependencies.extend(discover_pyproject(pyproject_file))
        pyproject_data = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
        dynamic_fields = pyproject_data.get("project", {}).get("dynamic", [])
        if any(
            field in {"dependencies", "optional-dependencies"}
            for field in dynamic_fields
        ):
            warnings.append(
                "Dynamic dependency fields in pyproject.toml are not resolved "
                "by PipSutra v0.1.0."
            )

    if not requirements_file.is_file() and not pyproject_file.is_file():
        warnings.append(
            "No supported manifest found (requirements.txt or pyproject.toml)."
        )

    # Keep separate source records but avoid exact duplicates.
    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in dependencies:
        key = (
            dependency.normalized_name,
            dependency.specifier,
            dependency.group,
        )
        unique.setdefault(key, dependency)

    return list(unique.values()), warnings


def _distribution_requirements(dist: metadata.Distribution) -> Iterable[Requirement]:
    for raw in dist.requires or []:
        try:
            requirement = Requirement(raw)
        except InvalidRequirement:
            continue
        if requirement.marker is None or requirement.marker.evaluate():
            yield requirement


def _metadata_search_paths(environment_path: Path) -> list[str]:
    """Find site-packages directories for a venv or an explicit metadata path."""
    candidates = [
        *environment_path.glob("lib/python*/site-packages"),
        environment_path / "Lib" / "site-packages",
        environment_path,
    ]
    return [str(path) for path in candidates if path.is_dir()]


def discover_installed(
    environment_path: Path,
) -> tuple[list[Package], list[DependencyEdge]]:
    # importlib.metadata reads distribution metadata from site-packages. It does
    # not import or execute the distributions' Python modules.
    search_paths = _metadata_search_paths(environment_path)
    distributions = list(metadata.distributions(path=search_paths))
    by_name: dict[str, metadata.Distribution] = {}
    packages: list[Package] = []

    for dist in distributions:
        name = dist.metadata["Name"]
        version = dist.version
        if not name or not version:
            continue
        normalized = canonicalize_name(name)
        by_name[normalized] = dist
        packages.append(
            Package(
                name=name,
                normalized_name=normalized,
                version=version,
                location=str(dist.locate_file("")),
            )
        )

    edges: list[DependencyEdge] = []
    for parent_name, dist in by_name.items():
        for requirement in _distribution_requirements(dist):
            child_name = canonicalize_name(requirement.name)
            if child_name in by_name:
                edges.append(
                    DependencyEdge(
                        parent=parent_name,
                        child=child_name,
                        requirement=str(requirement),
                        marker=str(requirement.marker) if requirement.marker else None,
                    )
                )

    return packages, edges


def build_inventory(
    project_path: str | Path, environment_path: str | Path
) -> Inventory:
    project = Path(project_path).expanduser().resolve()
    environment = Path(environment_path).expanduser().resolve()

    if not project.exists() or not project.is_dir():
        raise ValueError(f"Project directory does not exist: {project}")
    if not environment.exists() or not environment.is_dir():
        raise ValueError(f"Environment directory does not exist: {environment}")

    declared, warnings = discover_declared(project)
    packages, edges = discover_installed(environment)

    direct_names = {
        item.normalized_name
        for item in declared
        if item.group == "main" and item.active
    }
    installed_names = {item.normalized_name for item in packages}
    missing = sorted(direct_names - installed_names)

    # Compute transitive reachability from declared main dependencies.
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.parent, set()).add(edge.child)

    depth: dict[str, int] = {}
    queue = [(name, 0) for name in sorted(direct_names & installed_names)]
    while queue:
        node, current_depth = queue.pop(0)
        if node in depth and depth[node] <= current_depth:
            continue
        depth[node] = current_depth
        for child in sorted(adjacency.get(node, set())):
            if child not in depth or current_depth + 1 < depth[child]:
                queue.append((child, current_depth + 1))

    updated_packages = [
        package.model_copy(
            update={
                "direct": package.normalized_name in direct_names,
                "dependency_depth": depth.get(package.normalized_name),
            }
        )
        for package in packages
    ]

    if missing:
        warnings.append(
            "Some declared main dependencies are not installed in the selected "
            "environment: " + ", ".join(missing)
        )

    return Inventory(
        project_path=str(project),
        environment_path=str(environment),
        declared_dependencies=declared,
        packages=sorted(updated_packages, key=lambda item: item.normalized_name),
        edges=sorted(edges, key=lambda item: (item.parent, item.child)),
        missing_declared=missing,
        warnings=warnings,
        discovery_status="partial" if warnings or missing else "complete",
    )
