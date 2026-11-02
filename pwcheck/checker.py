"""Score passwords and turn regex findings into actionable advice.

The checker starts from a transparent 100 point scale: length, character
variety, uniqueness and extra length each contribute points. Weak patterns
found by :mod:`pwcheck.patterns` then subtract points, with a hard cap for
passwords that appear in the common-password list.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .patterns import (
    PatternMatch,
    find_patterns,
    has_digit,
    has_lowercase,
    has_symbol,
    has_uppercase,
    has_whitespace,
    is_only_digits,
)

__all__ = [
    "CHECKS",
    "PasswordReport",
    "analyze",
    "check_password",
    "entropy_bits",
    "score_to_label",
    "strength_label",
]

#: The positive checks shown by the command line interface.
CHECKS: tuple[tuple[str, str], ...] = (
    ("length_8", "At least 8 characters"),
    ("length_12", "At least 12 characters"),
    ("length_16", "At least 16 characters"),
    ("lowercase", "Contains a lower case letter"),
    ("uppercase", "Contains an upper case letter"),
    ("digit", "Contains a digit"),
    ("symbol", "Contains a symbol"),
    ("no_whitespace", "Contains no whitespace"),
    ("not_only_digits", "Is not made only of digits"),
)

#: Points subtracted for each pattern detected by :func:`find_patterns`.
PENALTIES: dict[str, int] = {
    "dictionary": 25,
    "repeated_char": 10,
    "repeated_block": 10,
    "sequence": 10,
    "keyboard": 10,
    "year": 5,
    "date": 5,
    "whitespace": 5,
}

LABELS: tuple[tuple[int, str], ...] = (
    (80, "Very strong"),
    (60, "Strong"),
    (40, "Fair"),
    (20, "Weak"),
    (0, "Very weak"),
)

_PASSPHRASE_RE = re.compile(r"^(?:\S+\s+){3,}\S+$")


@dataclass
class PasswordReport:
    """The result of checking a password."""

    length: int
    score: int
    label: str
    entropy_bits: float
    checks: dict[str, bool] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    @property
    def is_strong(self) -> bool:
        """``True`` when the rating is "Strong" or better."""
        return self.score >= 60

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation of the report."""
        return {
            "length": self.length,
            "score": self.score,
            "label": self.label,
            "entropy_bits": round(self.entropy_bits, 2),
            "checks": dict(self.checks),
            "warnings": list(self.warnings),
            "suggestions": list(self.suggestions),
        }


def score_to_label(score: int) -> str:
    """Return the human readable label for a 0-100 score."""
    for threshold, label in LABELS:
        if score >= threshold:
            return label
    return "Very weak"


def strength_label(score: int) -> str:
    """Alias for :func:`score_to_label` kept for a friendly public API."""
    return score_to_label(score)


def _charset_size(password: str) -> int:
    size = 0
    if has_lowercase(password):
        size += 26
    if has_uppercase(password):
        size += 26
    if has_digit(password):
        size += 10
    if has_symbol(password):
        size += 32
    if not size:
        size = len(set(password))
    return size


def entropy_bits(password: str) -> float:
    """Estimate the password's entropy in bits.

    This is a rough upper bound: it assumes every character was chosen
    independently at random from the detected character classes. Pattern
    penalties are reflected in the score, not in this number.
    """
    if not password:
        return 0.0
    size = _charset_size(password)
    if size <= 1:
        return 0.0
    return len(password) * math.log2(size)


def _length_points(length: int) -> int:
    points = 0
    if length >= 8:
        points += 10
    if length >= 12:
        points += 10
    if length >= 16:
        points += 10
    return points


def _variety_points(password: str) -> int:
    points = 0
    if has_lowercase(password):
        points += 10
    if has_uppercase(password):
        points += 10
    if has_digit(password):
        points += 10
    if has_symbol(password):
        points += 10
    return points


def _unique_points(password: str) -> int:
    if not password:
        return 0
    return round(15 * len(set(password)) / len(password))


def _length_bonus(length: int) -> int:
    return min(15, max(0, length - 8))


def _looks_like_passphrase(password: str) -> bool:
    """Return ``True`` for long, multi-word passphrases."""
    return len(password) >= 20 and _PASSPHRASE_RE.match(password.strip()) is not None


def _suggestions(
    password: str,
    patterns: list[PatternMatch],
    checks: dict[str, bool],
    passphrase: bool,
) -> list[str]:
    suggestions: list[str] = []
    length = len(password)
    keys = {pattern.key for pattern in patterns}

    if not password:
        return ["Choose a password (or better, a passphrase) with at least 12 characters."]

    if passphrase:
        if length >= 24:
            return ["Looks good - store it in a password manager and enable 2FA."]
        return ["Add another word or two to give the passphrase more margin."]

    if length < 8:
        suggestions.append("Use at least 8 characters; 12 or more is much better.")
    elif length < 12:
        suggestions.append("Add a few more characters; aim for 12 or more.")
    elif length < 16:
        suggestions.append("Use 16 or more characters to make offline cracking impractical.")

    if not checks["lowercase"]:
        suggestions.append("Add lower case letters.")
    if not checks["uppercase"]:
        suggestions.append("Add upper case letters.")
    if not checks["digit"]:
        suggestions.append("Add digits.")
    if not checks["symbol"]:
        suggestions.append("Add symbols such as ! @ # $ %.")

    if "common" in keys:
        suggestions.append("Avoid commonly used passwords entirely - they are cracked instantly.")
    if "dictionary" in keys:
        suggestions.append(
            "Avoid dictionary words and names; string random words together instead."
        )
    if keys & {"repeated_char", "repeated_block", "sequence", "keyboard"}:
        suggestions.append("Break up repeated, sequential or keyboard patterns.")
    if keys & {"year", "date"}:
        suggestions.append("Avoid years, birthdays and other guessable dates.")
    if "whitespace" in keys:
        suggestions.append("Avoid spaces; some systems handle them inconsistently.")
    if checks["not_only_digits"] is False:
        suggestions.append("Digits alone are easy to brute force; mix in letters and symbols.")

    if not suggestions:
        suggestions.append("Looks good - store it in a password manager and enable 2FA.")
    elif len(password) >= 16 and not keys:
        suggestions.append("Excellent - store it in a password manager and enable 2FA.")

    return suggestions


def check_password(password: str) -> PasswordReport:
    """Evaluate a password and suggest improvements.

    Args:
        password: The password to check.

    Returns:
        A :class:`PasswordReport` with a 0-100 score, a rating, the individual
        checks, warnings about weak patterns and concrete suggestions.
    """
    password = password or ""
    length = len(password)

    checks = {
        "length_8": length >= 8,
        "length_12": length >= 12,
        "length_16": length >= 16,
        "lowercase": has_lowercase(password),
        "uppercase": has_uppercase(password),
        "digit": has_digit(password),
        "symbol": has_symbol(password),
        "no_whitespace": not has_whitespace(password),
        "not_only_digits": not is_only_digits(password),
    }

    passphrase = _looks_like_passphrase(password)
    patterns = [
        pattern
        for pattern in find_patterns(password)
        if not (passphrase and pattern.key == "whitespace")
    ]
    warnings = [pattern.description for pattern in patterns]

    class_count = sum(
        checks[name] for name in ("lowercase", "uppercase", "digit", "symbol")
    )
    if password and class_count <= 1 and not passphrase:
        warnings.append("It uses only one character type.")
    if is_only_digits(password) and password:
        warnings.append("It is made only of digits.")

    score = _length_points(length) + _variety_points(password)
    score += _unique_points(password) + _length_bonus(length)

    if "common" in {pattern.key for pattern in patterns}:
        score = min(score, 5)

    if password and class_count <= 1 and not passphrase:
        score -= 15
    if is_only_digits(password) and password:
        score -= 10

    for pattern in patterns:
        score -= PENALTIES.get(pattern.key, 0)

    score = max(0, min(100, score))

    return PasswordReport(
        length=length,
        score=score,
        label=score_to_label(score),
        entropy_bits=entropy_bits(password),
        checks=checks,
        warnings=warnings,
        suggestions=_suggestions(password, patterns, checks, passphrase),
    )


#: Friendly alias so ``from pwcheck import analyze`` reads naturally.
analyze = check_password
