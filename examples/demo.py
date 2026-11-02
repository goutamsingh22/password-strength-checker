"""Print a small strength report for a handful of example passwords."""

from __future__ import annotations

from pwcheck import check_password

SAMPLES = [
    "",
    "password",
    "Summer2024!",
    "Tr0ub4dor&3",
    "correct horse battery staple",
    "Kq7#vR2$xLp9!zWc4&",
]


def main() -> None:
    for password in SAMPLES:
        report = check_password(password)
        shown = password or "(empty)"
        print(f"{report.label:<11} {report.score:>3}/100  {shown}")
        for warning in report.warnings:
            print(f"    ! {warning}")
        print(f"    -> {report.suggestions[0]}")


if __name__ == "__main__":
    main()
