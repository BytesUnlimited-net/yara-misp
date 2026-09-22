# test_yara_generator.py
from pathlib import Path

import yara_scan

def test_no_match(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(yara_scan, "yara_dir", tmp_path / "yara_dir")

    yara_file = Path(f"{yara_scan.yara_dir}/test.yar")
    yara_file.parent.mkdir(parents=True, exist_ok=True)
    yara_file.write_text("rule Dummy { condition: false }")

    test_file = tmp_path / "test.exe"
    test_file.write_text("test")
    yara_scan.main(test_file)

    captured = capsys.readouterr()
    assert "Event ID" not in captured.out


def test_match(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(yara_scan, "yara_dir", tmp_path / "yara_dir")

    yara_file = Path(f"{yara_scan.yara_dir}/test.yar")
    yara_file.parent.mkdir(parents=True, exist_ok=True)
    yara_file.write_text('rule Dummy { meta: event_id = 1 attr_uuid = "" condition: true }')

    test_file = tmp_path / "test.exe"
    test_file.write_text("test")
    yara_scan.main(test_file)

    captured = capsys.readouterr()
    assert "Event ID" in captured.out
