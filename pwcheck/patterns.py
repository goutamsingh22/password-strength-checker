"""Regular expressions and word lists used to spot weak password patterns.

Every rule in this module is a compiled :mod:`re` pattern or a small lookup
table. Keeping the rules here makes the scoring code in :mod:`pwcheck.checker`
easy to read and the patterns easy to test in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "COMMON_PASSWORDS",
    "DICTIONARY_WORDS",
    "PatternMatch",
    "find_patterns",
    "has_digit",
    "has_lowercase",
    "has_symbol",
    "has_uppercase",
    "has_whitespace",
    "is_only_digits",
    "is_only_letters",
]

# --------------------------------------------------------------------------- #
# character class rules
# --------------------------------------------------------------------------- #
LOWERCASE_RE = re.compile(r"[a-z]")
UPPERCASE_RE = re.compile(r"[A-Z]")
DIGIT_RE = re.compile(r"\d")
SYMBOL_RE = re.compile(r"[^A-Za-z0-9\s]")
WHITESPACE_RE = re.compile(r"\s")
ONLY_DIGITS_RE = re.compile(r"^\d+$")
ONLY_LETTERS_RE = re.compile(r"^[A-Za-z]+$")


def has_lowercase(password: str) -> bool:
    """Return ``True`` when the password contains a lower case letter."""
    return LOWERCASE_RE.search(password) is not None


def has_uppercase(password: str) -> bool:
    """Return ``True`` when the password contains an upper case letter."""
    return UPPERCASE_RE.search(password) is not None


def has_digit(password: str) -> bool:
    """Return ``True`` when the password contains a digit."""
    return DIGIT_RE.search(password) is not None


def has_symbol(password: str) -> bool:
    """Return ``True`` when the password contains a non-alphanumeric symbol."""
    return SYMBOL_RE.search(password) is not None


def has_whitespace(password: str) -> bool:
    """Return ``True`` when the password contains whitespace."""
    return WHITESPACE_RE.search(password) is not None


def is_only_digits(password: str) -> bool:
    """Return ``True`` when the password consists only of digits."""
    return ONLY_DIGITS_RE.match(password) is not None


def is_only_letters(password: str) -> bool:
    """Return ``True`` when the password consists only of letters."""
    return ONLY_LETTERS_RE.match(password) is not None


# --------------------------------------------------------------------------- #
# pattern rules
# --------------------------------------------------------------------------- #
def _runs(source: str, size: int = 3) -> set[str]:
    """Return every forward and backward run of ``size`` characters."""
    runs: set[str] = set()
    for index in range(len(source) - size + 1):
        chunk = source[index : index + size]
        runs.add(chunk)
        runs.add(chunk[::-1])
    return runs


def _alternation(parts: set[str] | tuple[str, ...]) -> str:
    """Build a regex alternation, longest alternatives first."""
    ordered = sorted(parts, key=len, reverse=True)
    return "|".join(re.escape(part) for part in ordered)


_ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz0123456789"
_KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "0123456789",
    "1qaz2wsx3edc",
    "qazwsxedc",
)

_SEQUENCE_RUNS = _runs(_ALPHANUMERIC) | _runs("0123456789")
_KEYBOARD_RUNS = set().union(*(_runs(row, size=4) for row in _KEYBOARD_ROWS))

SEQUENCE_RE = re.compile(_alternation(_SEQUENCE_RUNS), re.IGNORECASE)
KEYBOARD_RE = re.compile(_alternation(_KEYBOARD_RUNS), re.IGNORECASE)

REPEATED_CHAR_RE = re.compile(r"(.)\1{2,}")
REPEATED_BLOCK_RE = re.compile(r"(.{2,}?)\1+")

YEAR_RE = re.compile(r"(?<!\d)(?:19|20)\d{2}(?!\d)")
DATE_RE = re.compile(r"(?<!\d)\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}(?!\d)")

#: The most frequently leaked passwords. These are worthless regardless of
#: length or how many character classes they use.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "abc123",
        "football",
        "monkey",
        "shadow",
        "master",
        "666666",
        "qwertyuiop",
        "123321",
        "mustang",
        "1234567890",
        "michael",
        "654321",
        "superman",
        "1qaz2wsx",
        "7777777",
        "121212",
        "000000",
        "qazwsx",
        "123qwe",
        "killer",
        "trustno1",
        "jordan",
        "jennifer",
        "zxcvbnm",
        "asdfgh",
        "hunter",
        "buster",
        "soccer",
        "harley",
        "batman",
        "andrew",
        "tigger",
        "sunshine",
        "iloveyou",
        "2000",
        "charlie",
        "robert",
        "thomas",
        "hockey",
        "ranger",
        "daniel",
        "starwars",
        "112233",
        "george",
        "computer",
        "michelle",
        "jessica",
        "pepper",
        "1111",
        "zxcvbn",
        "555555",
        "11111111",
        "131313",
        "freedom",
        "777777",
        "pass",
        "maggie",
        "159753",
        "aaaaaa",
        "ginger",
        "princess",
        "joshua",
        "cheese",
        "amanda",
        "summer",
        "love",
        "ashley",
        "6969",
        "nicole",
        "chelsea",
        "biteme",
        "matthew",
        "access",
        "yankees",
        "987654321",
        "dallas",
        "austin",
        "thunder",
        "taylor",
        "matrix",
        "william",
        "corvette",
        "hello",
        "martin",
        "heather",
        "secret",
        "merlin",
        "diamond",
        "1234qwer",
        "hammer",
        "silver",
        "222222",
        "88888888",
        "anthony",
        "justin",
        "test",
        "bailey",
        "q1w2e3r4t5",
        "patrick",
        "internet",
        "scooter",
        "orange",
        "11111",
        "golfer",
        "cookie",
        "richard",
        "samantha",
        "bigdog",
        "guitar",
        "jackson",
        "whatever",
        "mickey",
        "chicken",
        "sparky",
        "snoopy",
        "maverick",
        "phoenix",
        "camaro",
        "peanut",
        "morgan",
        "welcome",
        "falcon",
        "andrea",
        "mercedes",
        "spider",
        "diablo",
        "lovers",
        "alpha",
        "brandon",
        "tucker",
        "elizabeth",
        "willie",
        "houston",
        "miller",
        "parker",
        "sandra",
        "admin",
        "administrator",
        "root",
        "user",
        "guest",
        "login",
        "letmein",
        "welcome1",
        "qwerty123",
        "password1",
        "passw0rd",
        "p@ssw0rd",
        "iloveyou1",
        "abc123456",
        "abcd1234",
        "1q2w3e4r",
    }
)

#: Words that are frequently used as the base of a password. The checker also
#: looks for these after undoing common leetspeak substitutions.
DICTIONARY_WORDS: tuple[str, ...] = (
    "password",
    "passphrase",
    "administrator",
    "admin",
    "welcome",
    "iloveyou",
    "letmein",
    "login",
    "master",
    "dragon",
    "monkey",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "trustno1",
    "superman",
    "batman",
    "starwars",
    "whatever",
    "freedom",
    "secret",
    "computer",
    "internet",
    "troubador",
    "troubadour",
    "trouble",
    "soccer",
    "hockey",
    "killer",
    "ranger",
    "harley",
    "daniel",
    "thomas",
    "tigger",
    "charlie",
    "ashley",
    "amanda",
    "nicole",
    "jessica",
    "michelle",
    "pepper",
    "ginger",
    "maggie",
    "cookie",
    "chicken",
    "sparky",
    "snoopy",
    "maverick",
    "phoenix",
    "peanut",
    "morgan",
    "corvette",
    "mustang",
    "diamond",
    "silver",
    "hammer",
    "summer",
    "winter",
    "spring",
    "autumn",
    "qwerty",
    "azerty",
    "keyboard",
    "google",
    "facebook",
    "instagram",
    "twitter",
    "github",
    "linkedin",
    "microsoft",
    "apple",
    "amazon",
    "london",
    "paris",
    "tokyo",
    "mumbai",
    "india",
    "america",
    "jesus",
    "money",
    "lovely",
    "banana",
    "orange",
)

DICTIONARY_RE = re.compile(_alternation(DICTIONARY_WORDS), re.IGNORECASE)

_LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
        "+": "t",
    }
)


@dataclass(frozen=True)
class PatternMatch:
    """A weak pattern detected inside a password."""

    key: str
    text: str
    description: str


def _normalise(password: str) -> str:
    """Lower-case a password and undo common leetspeak substitutions."""
    return password.lower().translate(_LEET_MAP)


def find_patterns(password: str) -> list[PatternMatch]:
    """Find every known weak pattern in ``password``.

    Args:
        password: The password to inspect.

    Returns:
        A list of :class:`PatternMatch` objects, ordered from most to least
        important.
    """
    if not password:
        return []

    normalised = _normalise(password)
    matches: list[PatternMatch] = []
    seen: set[str] = set()

    def add(key: str, text: str, description: str) -> None:
        if key not in seen:
            seen.add(key)
            matches.append(PatternMatch(key, text, description))

    if normalised in COMMON_PASSWORDS:
        add("common", password, "It is one of the most commonly used passwords.")

    dictionary = DICTIONARY_RE.search(normalised)
    if dictionary and normalised not in COMMON_PASSWORDS:
        add(
            "dictionary",
            dictionary.group(0),
            f"It contains the common word '{dictionary.group(0)}'.",
        )

    repeated_char = REPEATED_CHAR_RE.search(password)
    if repeated_char:
        add(
            "repeated_char",
            repeated_char.group(0),
            f"It repeats the character '{repeated_char.group(1)}' three or more times.",
        )

    repeated_block = REPEATED_BLOCK_RE.search(password)
    if repeated_block and len(set(repeated_block.group(1))) > 1:
        add(
            "repeated_block",
            repeated_block.group(0),
            f"It repeats the block '{repeated_block.group(1)}'.",
        )

    sequence = SEQUENCE_RE.search(password)
    if sequence:
        add("sequence", sequence.group(0), f"It contains the sequence '{sequence.group(0)}'.")

    keyboard = KEYBOARD_RE.search(password)
    if keyboard:
        add(
            "keyboard",
            keyboard.group(0),
            f"It follows the keyboard pattern '{keyboard.group(0)}'.",
        )

    date = DATE_RE.search(password)
    if date:
        add("date", date.group(0), f"It contains the date '{date.group(0)}'.")

    year = YEAR_RE.search(password)
    if year:
        add("year", year.group(0), f"It contains the year '{year.group(0)}'.")

    if has_whitespace(password):
        add("whitespace", " ", "It contains whitespace, which some systems mishandle.")

    return matches
