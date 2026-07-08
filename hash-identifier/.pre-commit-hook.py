#!/usr/bin/env python3
"""
Pre-commit hook to prevent accidental commits of password hashes.

This hook runs on all changed files and checks each line for high-confidence
hash matches. If found, it blocks the commit and prints a warning.

Exit codes:
    0 = commit allowed (no violations found)
    1 = commit blocked (hash-like strings found)
"""

import sys
from hash_identifier import identify


def has_pragma_allowlist(line: str) -> bool:
    """Check if the line contains the allowlist comment."""
    return "# pragma: allow-hash" in line


def is_violation(line: str) -> bool:
    """
    Return True if the line contains something that looks like a real hash.
    
    A violation is a line where:
    - identify() returns at least one candidate
    - The top candidate has HIGH confidence
    - The algorithm is NOT a generic/unknown match
    """
    if not line.strip():
        return False
    
    candidates = identify(line)
    if not candidates:
        return False
    
    top_candidate = candidates[0]

    # Block if confidence is high
    if top_candidate.confidence != "high":
        return False
    
    # Don't block generic or "not a hash" candidates
    algorithm = top_candidate.algorithm
    if algorithm.startswith("PHC string"):
        return False
    if "(not a hash)" in algorithm:
        return False
    
    return True


def main():
    """
    Process all filenames passed as arguments.
    
    Pre-commit passes filenames as command-line arguments.
    For each file, read line-by-line and check for violations.
    """
    violations_found = False

    for filename in sys.argv[1:]:
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    # Skip allowlisted lines
                    if has_pragma_allowlist(line):
                        continue

                    # Check if this line is a violation
                    if is_violation(line):
                        violations_found = True
                        print(
                            f"{filename}:{line_num}: Potential hash detected: {line.strip()[:60]}"
                        )
                        print(f"Add '# pragma: allow-hash' to the end of the line to allowlist it")

        except Exception as e:
            print(f"Error reading {filename}: {e}", file=sys.stderr)
            violations_found = True

    sys.exit(1 if violations_found else 0)


if __name__ == "__main__":
    main()