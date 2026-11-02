# pwcheck - Regex Password Strength Checker

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-28%20passing-brightgreen.svg)](tests)
[![No dependencies](https://img.shields.io/badge/dependencies-0-informational.svg)](pyproject.toml)

A fast, **dependency-free** password strength checker written in Python. It uses
compiled regular expressions to find weak patterns, scores a password out of
100, explains exactly what is wrong, and suggests concrete improvements.

---

## Features

| Feature | Description |
| --- | --- |
| Regex rule engine | Character classes, repeats, sequences, keyboard runs, dates and years |
| Common-password guard | Leaked passwords such as `password` or `123456` are capped at a very low score |
| Leetspeak-aware dictionary check | Detects `Tr0ub4dor&3` as containing the word `troubador` |
| 0-100 score | Five ratings from **Very weak** to **Very strong** |
| Actionable feedback | A warning for every pattern found and a suggestion for every gap |
| Python library | `check_password()` returns a typed, JSON-serialisable report |
| CLI with JSON mode | Human-friendly output for terminals, `--json` for scripts |
| CI friendly | `--min-score` exits with status `1` when a password is too weak |
| No dependencies | Pure standard library, Python 3.8+ |

---

## Installation

```bash
# from a clone
git clone https://github.com/goutamsingh22/password-strength-checker.git
cd password-strength-checker
pip install .

# development install with the test tools
pip install -e ".[dev]"
```

You can also run it directly from the source tree:

```bash
python -m pwcheck 'Tr0ub4dor&3'
```

---

## Quick start

```bash
# check one password
pwcheck 'Tr0ub4dor&3'

# JSON output for scripts
pwcheck --json 'correct horse battery staple'

# read the password from stdin (nothing is echoed)
printf '%s' 'Summer2024!' | pwcheck

# fail a CI step when the password is weaker than 60/100
pwcheck --min-score 60 'password' || echo "password is too weak"
```

```text
 ____            ____ _               _
|  _ \ __      __/ ___| |__   ___  ___| | __
| |_) \ \ /\ / / |   | '_ \ / _ \/ __| |/ /
|  __/ \ V  V /| |___| | | |  __/ (__|   <
|_|     \_/\_/  \____|_| |_|\___|\___|_|\_\

Strength  : Fair (42/100)
Length    : 11 characters
Entropy   : 72.1 bits (upper bound)

Checks:
  [x] At least 8 characters
  [ ] At least 12 characters
  [ ] At least 16 characters
  [x] Contains a lower case letter
  [x] Contains an upper case letter
  [x] Contains a digit
  [x] Contains a symbol
  [x] Contains no whitespace
  [x] Is not made only of digits

Warnings:
  - It contains the common word 'troubador'.

Suggestions:
  - Add a few more characters; aim for 12 or more.
  - Avoid dictionary words and names; string random words together instead.
```

When no password is given on the command line, `pwcheck` reads from stdin. If
stdin is a terminal it prompts with hidden input instead of echoing the password.

---

## How the score works

The checker starts at **0** and adds up to **100** points:

| Rule | Points |
| --- | --- |
| Length >= 8 / >= 12 / >= 16 | 10 each |
| Lower case letters | 10 |
| Upper case letters | 10 |
| Digits | 10 |
| Symbols | 10 |
| Unique-character ratio (up to) | 15 |
| Extra length beyond 8 (up to) | 15 |

Weak patterns then subtract points:

| Pattern | Penalty |
| --- | --- |
| Common password | score capped at 5 |
| Dictionary word (leet-aware) | -25 |
| Repeated character (`aaa`) | -10 |
| Repeated block (`abcabc`) | -10 |
| Sequential run (`abc`, `123`) | -10 |
| Keyboard run (`qwe`, `asd`) | -10 |
| Year / date | -5 each |
| Whitespace | -5 |
| Only one character class | -15 |
| Digits only | -10 |

| Score | Rating |
| --- | --- |
| 80-100 | Very strong |
| 60-79 | Strong |
| 40-59 | Fair |
| 20-39 | Weak |
| 0-19 | Very weak |

The score is a heuristic, not a proof of security. A password that is not in a
breach list can still be predictable, so combine this tool with a password
manager and multi-factor authentication.

---

## Regex rules

All rules live in [`pwcheck/patterns.py`](pwcheck/patterns.py) and are compiled
once at import time:

| Rule | Regex | Example match |
| --- | --- | --- |
| Lower case | `[a-z]` | `a` |
| Upper case | `[A-Z]` | `A` |
| Digit | `\d` | `7` |
| Symbol | `[^A-Za-z0-9\s]` | `#` |
| Whitespace | `\s` | ` ` |
| Repeated character | `(.)\1{2,}` | `aaaa` |
| Repeated block | `(.{2,}?)\1+` | `abcabc` |
| Sequential run | alternation of all 3-character alphabet/digit runs | `abc`, `432` |
| Keyboard run | alternation of all 4-character keyboard rows | `qwer`, `asdf` |
| Year | `(?<!\d)(?:19|20)\d{2}(?!\d)` | `2024` |
| Date | `(?<!\d)\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}(?!\d)` | `12/25/2024` |

The sequence and keyboard alternations are generated at import time, so adding
a row or alphabet is a one-line change.

---

## Library usage

```python
from pwcheck import check_password, find_patterns

report = check_password("Tr0ub4dor&3")

print(report.score)          # 42
print(report.label)          # Fair
print(report.is_strong)      # False
print(report.entropy_bits)   # 72.1 (rough upper bound)
print(report.warnings)       # ["It contains the common word 'troubador'."]
print(report.suggestions)    # ["Add a few more characters; aim for 12 or more.", ...]

for pattern in find_patterns("abcabc2024"):
    print(pattern.key, pattern.text, pattern.description)
```

`report.to_dict()` returns a plain dictionary that is safe to pass to
`json.dumps()`.

---

## CLI reference

```text
usage: pwcheck [-h] [-j] [-q] [--min-score N] [--version] [password]

positional arguments:
  password         password to check (prompted for or read from stdin when omitted)

options:
  -h, --help       show this help message and exit
  -j, --json       print the report as JSON
  -q, --quiet      print only the rating
  --min-score N    exit with status 1 when the score is below N (0-100)
  --version        show program's version number and exit
```

Exit codes: `0` on success, `1` when `--min-score` is not met, `2` when no
password could be read or the arguments are invalid.

---

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
ruff check .
python examples/demo.py
```

The test suite covers every regex rule, the scoring boundaries, the suggestion
engine, JSON serialisation and the CLI including stdin and exit codes.

---

## Security notes

- Passwords are checked locally. Nothing is sent over the network or written to
  disk.
- The CLI uses `getpass` so typed passwords are not echoed.
- Avoid passing secrets as command-line arguments on shared machines: they can
  appear in your shell history and process list. Prefer stdin or the hidden
  prompt.
- This tool estimates weakness. It does not replace a breach check, a password
  manager or multi-factor authentication.

---

## License

MIT - see [LICENSE](LICENSE).
