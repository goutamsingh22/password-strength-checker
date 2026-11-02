"""Tests for the regex patterns and the scoring engine."""

from __future__ import annotations

import json

from pwcheck.checker import CHECKS, check_password, entropy_bits, strength_label
from pwcheck.patterns import find_patterns


def test_empty_password_is_very_weak() -> None:
    report = check_password("")
    assert report.length == 0
    assert report.score == 0
    assert report.label == "Very weak"
    assert report.is_strong is False
    assert report.suggestions


def test_strong_password_scores_high() -> None:
    report = check_password("Kq7#vR2$xLp9!zWc4&")
    assert report.score >= 80
    assert report.label == "Very strong"
    assert report.is_strong is True
    assert report.warnings == []
    assert find_patterns("Kq7#vR2$xLp9!zWc4&") == []


def test_longer_is_stronger() -> None:
    short = check_password("Kq7#")
    longer = check_password("Kq7#vR2$xLp9")
    assert longer.score > short.score


def test_common_password_is_penalised() -> None:
    report = check_password("password")
    assert report.score <= 10
    assert report.label == "Very weak"
    assert any("commonly used" in warning for warning in report.warnings)


def test_leetspeak_dictionary_word_is_detected() -> None:
    report = check_password("Tr0ub4dor&3")
    assert any("common word" in warning for warning in report.warnings)
    assert report.is_strong is False


def test_repeated_characters_are_detected() -> None:
    report = check_password("aaaB3!xyz")
    assert any("repeats the character" in warning for warning in report.warnings)


def test_repeated_block_is_detected() -> None:
    report = check_password("abcabcX9!")
    assert any("repeats the block" in warning for warning in report.warnings)


def test_sequence_is_detected() -> None:
    report = check_password("abcdefgh")
    assert any("sequence" in warning for warning in report.warnings)


def test_keyboard_pattern_is_detected() -> None:
    report = check_password("asdfghjk")
    assert any("keyboard pattern" in warning for warning in report.warnings)


def test_year_and_date_are_detected() -> None:
    report = check_password("Kq7#vR2$xLp9!zWc2024")
    assert any("year" in warning for warning in report.warnings)

    dated = check_password("Summer-12/25/2024!")
    assert any("date" in warning for warning in dated.warnings)
    assert any("year" in warning for warning in dated.warnings)


def test_whitespace_is_detected() -> None:
    report = check_password("Hello World1!")
    assert any("whitespace" in warning for warning in report.warnings)
    assert report.checks["no_whitespace"] is False


def test_only_digits_is_penalised() -> None:
    report = check_password("9871236540")
    assert report.label in {"Very weak", "Weak"}
    assert any("only of digits" in warning for warning in report.warnings)
    assert report.checks["not_only_digits"] is False


def test_single_character_class_is_reported() -> None:
    report = check_password("alllowercaseletters")
    assert any("one character type" in warning for warning in report.warnings)
    assert report.is_strong is False


def test_missing_classes_produce_suggestions() -> None:
    report = check_password("lowercase")
    suggestions = " ".join(report.suggestions).lower()
    assert "upper case" in suggestions
    assert "digits" in suggestions
    assert "symbols" in suggestions


def test_checks_cover_the_public_contract() -> None:
    report = check_password("Example1!")
    assert set(report.checks) == {key for key, _ in CHECKS}


def test_report_is_json_serialisable() -> None:
    data = check_password("Tr0ub4dor&3").to_dict()
    encoded = json.dumps(data)
    assert "entropy_bits" in encoded
    assert isinstance(data["warnings"], list)
    assert isinstance(data["suggestions"], list)
    assert isinstance(data["checks"], dict)


def test_entropy_is_zero_when_empty() -> None:
    assert entropy_bits("") == 0.0
    assert entropy_bits("Kq7#vR2$xLp9") > 60


def test_labels() -> None:
    assert strength_label(0) == "Very weak"
    assert strength_label(19) == "Very weak"
    assert strength_label(20) == "Weak"
    assert strength_label(40) == "Fair"
    assert strength_label(60) == "Strong"
    assert strength_label(80) == "Very strong"
    assert strength_label(100) == "Very strong"


def test_passphrase_is_reasonable() -> None:
    report = check_password("Correct-Horse-Battery-Staple-42!")
    assert report.is_strong is True
    assert report.warnings == []


def test_lowercase_passphrase_is_not_penalised() -> None:
    report = check_password("correct horse battery staple")
    assert report.is_strong is True
    assert report.warnings == []
    assert report.suggestions == [
        "Looks good - store it in a password manager and enable 2FA."
    ]
