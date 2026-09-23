
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

import yara_scan


# -------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------

@pytest.fixture
def mock_yara_dir(tmp_path, monkeypatch):
    """
    Replace the scanner's YARA directory and compiled file
    with temporary paths.
    """
    yara_dir = tmp_path / "yara"
    yara_dir.mkdir()

    compiled_file = yara_dir / "rules.compiled"

    monkeypatch.setattr(yara_scan, "yara_dir", yara_dir)
    monkeypatch.setattr(yara_scan, "compiled_file", compiled_file)

    return yara_dir, compiled_file


@pytest.fixture
def target_file(tmp_path):
    """
    Create a temporary target file to scan.
    """
    target = tmp_path / "sample.txt"
    target.write_text("test content")

    return target


@pytest.fixture
def mock_rules():
    """
    Mock compiled YARA rules.
    """
    rules = MagicMock()
    rules.match.return_value = []

    return rules


@pytest.fixture
def yara_match():
    """
    Mock a YARA match with metadata.
    """
    return SimpleNamespace(
        meta={
            "event_id": "123",
            "attr_uuid": "abc-123",
        },
        namespace="default",
        rule="TestRule",
        strings=[],
        tags=[],
    )


# -------------------------------------------------------------------
# Tests: Error handling
# -------------------------------------------------------------------

def test_no_yara_files_raises_runtime_error(
    mock_yara_dir,
    target_file,
):
    """
    main() should raise RuntimeError when no .yar files exist.
    """
    with pytest.raises(RuntimeError, match="No .yar files found"):
        yara_scan.main(target_file)


# -------------------------------------------------------------------
# Tests: Compilation
# -------------------------------------------------------------------

def test_compiles_rules_when_compiled_file_does_not_exist(
    mock_yara_dir,
    target_file,
    monkeypatch,
):
    """
    If the compiled file does not exist, rules should be compiled
    and saved.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    mock_rules = MagicMock()
    mock_rules.match.return_value = []

    mock_compile = MagicMock(return_value=mock_rules)

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        mock_compile,
    )

    yara_scan.main(target_file)

    mock_compile.assert_called_once_with(
        filepaths={
            "test.yar": str(rule_file),
        }
    )

    mock_rules.save.assert_called_once_with(
        str(compiled_file)
    )

    mock_rules.match.assert_called_once_with(
        str(target_file)
    )


def test_compiles_rules_when_compiled_file_is_outdated(
    mock_yara_dir,
    target_file,
    monkeypatch,
):
    """
    If a .yar file is newer than the compiled file,
    the scanner should recompile.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    compiled_file.write_bytes(b"old compiled rules")

    # Make the compiled file older than the rule file.
    os.utime(compiled_file, (100, 100))
    os.utime(rule_file, (200, 200))

    mock_rules = MagicMock()
    mock_rules.match.return_value = []

    mock_compile = MagicMock(return_value=mock_rules)

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        mock_compile,
    )

    yara_scan.main(target_file)

    mock_compile.assert_called_once()

    mock_rules.save.assert_called_once_with(
        str(compiled_file)
    )


def test_loads_compiled_rules_when_up_to_date(
    mock_yara_dir,
    target_file,
    monkeypatch,
):
    """
    If the compiled file is newer than all .yar files,
    the scanner should load it instead of recompiling.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    compiled_file.write_bytes(b"compiled rules")

    # Make the compiled file newer than the rule file.
    os.utime(rule_file, (100, 100))
    os.utime(compiled_file, (200, 200))

    mock_rules = MagicMock()
    mock_rules.match.return_value = []

    mock_compile = MagicMock()
    mock_load = MagicMock(return_value=mock_rules)

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        mock_compile,
    )

    monkeypatch.setattr(
        yara_scan.yara,
        "load",
        mock_load,
    )

    yara_scan.main(target_file)

    mock_compile.assert_not_called()

    mock_load.assert_called_once_with(
        str(compiled_file)
    )

    mock_rules.match.assert_called_once_with(
        str(target_file)
    )


# -------------------------------------------------------------------
# Tests: Multiple YARA rule files
# -------------------------------------------------------------------

def test_compiles_all_yara_files(
    mock_yara_dir,
    target_file,
    monkeypatch,
):
    """
    All .yar files should be included in the compilation.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file_1 = yara_dir / "rule1.yar"
    rule_file_2 = yara_dir / "rule2.yar"

    rule_file_1.write_text("rule Rule1 { condition: true }")
    rule_file_2.write_text("rule Rule2 { condition: true }")

    mock_rules = MagicMock()
    mock_rules.match.return_value = []

    mock_compile = MagicMock(return_value=mock_rules)

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        mock_compile,
    )

    yara_scan.main(target_file)

    mock_compile.assert_called_once()

    filepaths = mock_compile.call_args.kwargs["filepaths"]

    assert filepaths == {
        "rule1.yar": str(rule_file_1),
        "rule2.yar": str(rule_file_2),
    }


# -------------------------------------------------------------------
# Tests: YARA matching
# -------------------------------------------------------------------

def test_matches_target_file(
    mock_yara_dir,
    target_file,
    monkeypatch,
    mock_rules,
):
    """
    The scanner should call match() with the target file path.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        MagicMock(return_value=mock_rules),
    )

    yara_scan.main(target_file)

    mock_rules.match.assert_called_once_with(
        str(target_file)
    )


def test_no_matches_does_not_print_match_details(
    mock_yara_dir,
    target_file,
    monkeypatch,
    mock_rules,
    capsys,
):
    """
    When YARA returns no matches, no match metadata should be printed.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    mock_rules.match.return_value = []

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        MagicMock(return_value=mock_rules),
    )

    yara_scan.main(target_file)

    output = capsys.readouterr().out

    assert "Event ID:" not in output
    assert "Attribute ID:" not in output


# -------------------------------------------------------------------
# Tests: Match output and MISP URL
# -------------------------------------------------------------------

def test_prints_match_metadata(
    mock_yara_dir,
    target_file,
    monkeypatch,
    yara_match,
    capsys,
):
    """
    The scanner should print match metadata and MISP link.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    mock_rules = MagicMock()
    mock_rules.match.return_value = [yara_match]

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        MagicMock(return_value=mock_rules),
    )

    monkeypatch.setenv(
        "MISP_URL",
        "https://misp.example.com",
    )

    yara_scan.main(target_file)

    output = capsys.readouterr().out

    assert "Event ID: 123" in output
    assert "Attribute ID: abc-123" in output

    assert (
        "MISP Link: "
        "https://misp.example.com/events/view/123/"
        "focus:abc-123"
    ) in output

    assert "All data:" in output
    assert "default" in output
    assert "TestRule" in output


def test_uses_default_misp_url(
    mock_yara_dir,
    target_file,
    monkeypatch,
    yara_match,
    capsys,
):
    """
    If MISP_URL is not set, the scanner should use
    https://localhost.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    mock_rules = MagicMock()
    mock_rules.match.return_value = [yara_match]

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        MagicMock(return_value=mock_rules),
    )

    monkeypatch.delenv("MISP_URL", raising=False)

    yara_scan.main(target_file)

    output = capsys.readouterr().out

    assert (
        "MISP Link: "
        "https://localhost/events/view/123/"
        "focus:abc-123"
    ) in output


def test_uses_custom_misp_url(
    mock_yara_dir,
    target_file,
    monkeypatch,
    yara_match,
    capsys,
):
    """
    The scanner should use the MISP_URL environment variable.
    """
    yara_dir, compiled_file = mock_yara_dir

    rule_file = yara_dir / "test.yar"
    rule_file.write_text("rule TestRule { condition: true }")

    mock_rules = MagicMock()
    mock_rules.match.return_value = [yara_match]

    monkeypatch.setattr(
        yara_scan.yara,
        "compile",
        MagicMock(return_value=mock_rules),
    )

    monkeypatch.setenv(
        "MISP_URL",
        "http://custom-misp",
    )

    yara_scan.main(target_file)

    output = capsys.readouterr().out

    assert (
        "MISP Link: "
        "http://custom-misp/events/view/123/"
        "focus:abc-123"
    ) in output
