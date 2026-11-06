from __future__ import annotations

from pathlib import Path

import pytest

from pipsutra.static_analysis import _EXCLUDED, scan_python_source


def test_detects_high_signal_python_patterns(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import pickle\n"
        "import subprocess\n"
        "value = eval(user_input)\n"
        "subprocess.run(command, shell=True)\n"
        "pickle.loads(payload)\n",
        encoding="utf-8",
    )
    findings, warnings = scan_python_source(tmp_path)
    assert warnings == []
    assert {item.rule_id for item in findings} == {
        "DG-PY-001",
        "DG-PY-003",
        "DG-PY-004",
    }


def test_ignores_virtual_environment_and_handles_syntax_errors(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("eval(x)")
    (tmp_path / "broken.py").write_text("def broken(:\n")
    findings, warnings = scan_python_source(tmp_path)
    assert findings == []
    assert any("SyntaxError" in warning for warning in warnings)


def test_detects_os_system(tmp_path: Path) -> None:
    (tmp_path / "commands.py").write_text("import os\nos.system(command)\n")
    findings, _ = scan_python_source(tmp_path)
    assert [item.rule_id for item in findings] == ["DG-PY-002"]


def test_detects_import_aliases_without_flagging_unrelated_run_method(
    tmp_path: Path,
) -> None:
    (tmp_path / "aliases.py").write_text(
        "import subprocess as sp\n"
        "from pickle import loads as decode\n"
        "from os import system as shell\n"
        "sp.run(command, shell=True)\n"
        "decode(payload)\n"
        "shell(command)\n"
        "client.run(shell=True)\n",
        encoding="utf-8",
    )
    findings, _ = scan_python_source(tmp_path)
    assert {item.rule_id for item in findings} == {
        "DG-PY-002",
        "DG-PY-003",
        "DG-PY-004",
    }
    assert len(findings) == 3


# ---------------------------------------------------------------------------
# Excluded directory names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("excluded_dir", sorted(_EXCLUDED))
def test_all_excluded_directories_are_skipped(
    tmp_path: Path, excluded_dir: str
) -> None:
    """Every name in _EXCLUDED must be skipped, not just .venv."""
    excluded = tmp_path / excluded_dir
    excluded.mkdir()
    (excluded / "risky.py").write_text("eval(payload)\n", encoding="utf-8")
    findings, _ = scan_python_source(tmp_path)
    assert findings == [], f"{excluded_dir}/ was not excluded"


def test_excluded_directory_nested_deep_is_still_skipped(tmp_path: Path) -> None:
    """An excluded name appearing at any depth must be skipped."""
    deep = tmp_path / "src" / "lib" / "__pycache__" / "generated"
    deep.mkdir(parents=True)
    (deep / "cached.py").write_text("eval(x)\n", encoding="utf-8")
    # A legitimate file alongside it
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    findings, _ = scan_python_source(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# Rule isolation — each rule is detected independently
# ---------------------------------------------------------------------------


def test_exec_is_flagged_as_dg_py_001(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text("exec(user_code)\n", encoding="utf-8")
    findings, _ = scan_python_source(tmp_path)
    assert any(f.rule_id == "DG-PY-001" for f in findings)


def test_subprocess_without_shell_true_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text(
        "import subprocess\nsubprocess.run(['ls', '-la'])\n", encoding="utf-8"
    )
    findings, _ = scan_python_source(tmp_path)
    assert not any(f.rule_id == "DG-PY-003" for f in findings)


def test_subprocess_shell_false_explicit_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text(
        "import subprocess\nsubprocess.run(cmd, shell=False)\n", encoding="utf-8"
    )
    findings, _ = scan_python_source(tmp_path)
    assert not any(f.rule_id == "DG-PY-003" for f in findings)


# ---------------------------------------------------------------------------
# Unreadable file produces a warning, not a crash
# ---------------------------------------------------------------------------


def test_unreadable_file_produces_warning_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "locked.py"
    target.write_text("eval(x)\n", encoding="utf-8")

    original_read_text = Path.read_text

    def patched_read_text(self: Path, **kwargs: object) -> str:
        if self == target:
            raise OSError("Permission denied")
        return original_read_text(self, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", patched_read_text)
    findings, warnings = scan_python_source(tmp_path)
    assert findings == []
    assert any("locked.py" in w for w in warnings)


# ---------------------------------------------------------------------------
# No Python files produces a warning
# ---------------------------------------------------------------------------


def test_no_python_files_produces_warning(tmp_path: Path) -> None:
    findings, warnings = scan_python_source(tmp_path)
    assert findings == []
    assert any("No Python source files" in w for w in warnings)


# ---------------------------------------------------------------------------
# Finding fields are populated correctly
# ---------------------------------------------------------------------------


def test_finding_fields_are_populated(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(payload)\n", encoding="utf-8")
    findings, _ = scan_python_source(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "DG-PY-001"
    assert f.file == "app.py"
    assert f.line >= 1
    assert f.evidence
    assert f.recommendation
