from pathlib import Path

import pytest

from pipsutra.discovery import (
    _parse_requirement,
    build_inventory,
    discover_pyproject,
    discover_requirements,
)


def test_requirements_parsing(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests>=2.31\n# comment\nPillow==10.0\n")
    result = discover_requirements(manifest)
    assert [item.normalized_name for item in result] == ["requests", "pillow"]
    assert result[0].specifier == ">=2.31"


def test_pyproject_parsing(tmp_path: Path) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\ndependencies = ["httpx>=0.27"]\n'
        '[project.optional-dependencies]\ntest = ["pytest>=8"]\n'
    )
    result = discover_pyproject(manifest)
    assert len(result) == 2
    assert result[0].normalized_name == "httpx"
    assert result[1].group == "test"


def test_inventory_marks_missing_declared_dependency(tmp_path: Path) -> None:
    project = tmp_path / "project"
    environment = tmp_path / "environment"
    project.mkdir()
    environment.mkdir()
    (project / "requirements.txt").write_text("definitely-not-installed-pipsutra>=1\n")

    report = build_inventory(project, environment)

    assert report.missing_declared == ["definitely-not-installed-pipsutra"]
    assert report.discovery_status == "partial"
    assert report.packages == []


def test_installed_metadata_is_read_from_venv_site_packages(tmp_path: Path) -> None:
    project = tmp_path / "project"
    environment = tmp_path / ".venv"
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    project.mkdir()
    site_packages.mkdir(parents=True)
    (project / "requirements.txt").write_text("demo-lib>=1\n")
    dist_info = site_packages / "demo_lib-1.2.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: demo-lib\nVersion: 1.2\n\n"
    )
    report = build_inventory(project, environment)
    assert any(pkg.normalized_name == "demo-lib" for pkg in report.packages)
    assert report.packages[0].direct is True


def test_rejects_pep508_vcs_direct_reference() -> None:
    with pytest.raises(ValueError, match="VCS requirements"):
        _parse_requirement(
            "demo @ git+https://example.test/demo.git",
            source="requirements.txt:1",
        )


def test_builds_direct_and_transitive_dependency_depths(tmp_path: Path) -> None:
    project = tmp_path / "project"
    environment = tmp_path / ".venv"
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    project.mkdir()
    site_packages.mkdir(parents=True)
    (project / "requirements.txt").write_text("parent-lib>=1\n", encoding="utf-8")

    parent_info = site_packages / "parent_lib-1.0.dist-info"
    parent_info.mkdir()
    (parent_info / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        "Name: parent-lib\n"
        "Version: 1.0\n"
        "Requires-Dist: child-lib>=2\n\n",
        encoding="utf-8",
    )
    child_info = site_packages / "child_lib-2.0.dist-info"
    child_info.mkdir()
    (child_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: child-lib\nVersion: 2.0\n\n",
        encoding="utf-8",
    )

    report = build_inventory(project, environment)
    packages = {item.normalized_name: item for item in report.packages}
    assert packages["parent-lib"].direct is True
    assert packages["parent-lib"].dependency_depth == 0
    assert packages["child-lib"].direct is False
    assert packages["child-lib"].dependency_depth == 1
    assert [(edge.parent, edge.child) for edge in report.edges] == [
        ("parent-lib", "child-lib")
    ]


def test_requirement_environment_markers_control_active_roots(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        'only-old-python; python_version < "3.0"\n'
        'supported-python; python_version >= "3.11"\n',
        encoding="utf-8",
    )
    result = discover_requirements(manifest)
    assert result[0].active is False
    assert result[1].active is True
    assert result[0].marker == 'python_version < "3.0"'


def test_requirements_skips_pip_index_options_and_hashes(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "--index-url https://packages.example.test/simple\n"
        "--require-hashes\n"
        "demo-lib==1.0 --hash=sha256:abcdef\n",
        encoding="utf-8",
    )
    result = discover_requirements(manifest)
    assert len(result) == 1
    assert result[0].normalized_name == "demo-lib"


def test_dynamic_pyproject_dependencies_mark_inventory_partial(tmp_path: Path) -> None:
    project = tmp_path / "project"
    environment = tmp_path / "environment"
    project.mkdir()
    environment.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\ndynamic = ["dependencies"]\n',
        encoding="utf-8",
    )

    report = build_inventory(project, environment)
    assert report.discovery_status == "partial"
    assert any("Dynamic dependency fields" in warning for warning in report.warnings)


# ---------------------------------------------------------------------------
# Version-specifier mismatch
# ---------------------------------------------------------------------------


def test_installed_version_outside_declared_specifier_is_still_included(
    tmp_path: Path,
) -> None:
    """
    The discovery layer does not resolve specifiers — it reports what is
    installed.  A declared specifier of >=2.0 with version 1.0 installed is
    still surfaced; the mismatch is flagged in warnings.
    """
    project = tmp_path / "project"
    environment = tmp_path / ".venv"
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    project.mkdir()
    site_packages.mkdir(parents=True)
    # Declare >=2.0 but install 1.0 — a specifier mismatch
    (project / "requirements.txt").write_text("demo-lib>=2.0\n", encoding="utf-8")
    dist_info = site_packages / "demo_lib-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: demo-lib\nVersion: 1.0\n\n",
        encoding="utf-8",
    )
    report = build_inventory(project, environment)
    # Package is still discovered
    installed = {pkg.normalized_name: pkg for pkg in report.packages}
    assert "demo-lib" in installed
    assert installed["demo-lib"].version == "1.0"


# ---------------------------------------------------------------------------
# Duplicate declarations from multiple manifests
# ---------------------------------------------------------------------------


def test_duplicate_declarations_from_two_manifests_are_deduplicated(
    tmp_path: Path,
) -> None:
    """The same dependency in requirements.txt and pyproject.toml is not doubled."""
    project = tmp_path / "project"
    environment = tmp_path / "environment"
    project.mkdir()
    environment.mkdir()
    (project / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2.0"]\n', encoding="utf-8"
    )
    report = build_inventory(project, environment)
    names = [dep.normalized_name for dep in report.declared_dependencies]
    assert names.count("requests") == 1


# ---------------------------------------------------------------------------
# Editable / nested requirements raise ValueError
# ---------------------------------------------------------------------------


def test_editable_requirement_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Editable"):
        _parse_requirement("-e .", source="requirements.txt:1")


def test_nested_requirements_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Nested"):
        _parse_requirement("-r other.txt", source="requirements.txt:1")


# ---------------------------------------------------------------------------
# Optional groups are not treated as selected by default
# ---------------------------------------------------------------------------


def test_optional_dependency_group_is_not_active_as_main(tmp_path: Path) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\n[project.optional-dependencies]\ntest = ["pytest>=8"]\n',
        encoding="utf-8",
    )
    result = discover_pyproject(manifest)
    assert len(result) == 1
    assert result[0].group == "test"
    # It should not be counted as a main dependency
    assert result[0].group != "main"
