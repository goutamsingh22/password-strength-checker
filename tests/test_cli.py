"""Tests for the command line interface."""

from __future__ import annotations

import io
import json

import pytest

from pwcheck.cli import main


def test_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "Tr0ub4dor&3"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["label"] == "Fair"
    assert report["length"] == 11
    assert "suggestions" in report


def test_quiet_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--quiet", "Kq7#vR2$xLp9!zWc4&"]) == 0
    output = capsys.readouterr().out
    assert "Very strong" in output
    assert "100/100" in output or "/100" in output


def test_full_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["Summer2024!"]) == 0
    output = capsys.readouterr().out
    assert "Strength" in output
    assert "Checks:" in output
    assert "Warnings:" in output
    assert "Suggestions:" in output


def test_min_score_failure(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--quiet", "--min-score", "80", "password"]) == 1
    assert "Very weak" in capsys.readouterr().out


def test_min_score_success() -> None:
    assert main(["--quiet", "--min-score", "80", "Kq7#vR2$xLp9!zWc4&"]) == 0


def test_password_from_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("Tr0ub4dor&3\n"))
    assert main(["--quiet"]) == 0
    assert "Fair" in capsys.readouterr().out


def test_empty_stdin_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main([]) == 2
    assert "no password supplied" in capsys.readouterr().err


def test_invalid_min_score_exits() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--min-score", "101", "password"])
    assert excinfo.value.code == 2
