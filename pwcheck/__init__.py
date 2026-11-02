"""pwcheck - a regex-driven password strength checker.

Example:
    >>> from pwcheck import check_password
    >>> report = check_password("Kq7#vR2$xLp9!zWc4&")
    >>> report.is_strong
    True
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Goutam Singh"
__email__ = "25mcaa22@kristujayanti.com"
__license__ = "MIT"

from .checker import (
    CHECKS,
    PasswordReport,
    analyze,
    check_password,
    entropy_bits,
    score_to_label,
    strength_label,
)
from .patterns import COMMON_PASSWORDS, DICTIONARY_WORDS, PatternMatch, find_patterns

__all__ = [
    "__version__",
    "CHECKS",
    "COMMON_PASSWORDS",
    "DICTIONARY_WORDS",
    "PasswordReport",
    "PatternMatch",
    "analyze",
    "check_password",
    "entropy_bits",
    "find_patterns",
    "score_to_label",
    "strength_label",
]
