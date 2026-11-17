"""Shared checks for AI-written scam patterns. Used by the nightly writer on the PC and by the definitions build."""
import re

# Only plain phrase patterns: letters, digits, spaces, apostrophe, hyphen, alternation, groups and "optional".
# No wildcards or repetition, so a pattern can never be slow or match everything.
SAFE = re.compile(r"^[a-z0-9 '|()?-]{6,120}$")
MIN_WEIGHT, MAX_WEIGHT = 5, 15


def problem(pattern, benign=()):
    """Returns why a pattern is unacceptable, or None when it is fine."""
    if not SAFE.match(pattern):
        return "uses characters outside the allowed phrase syntax"
    if "||" in pattern or "()" in pattern or pattern.startswith("|") or pattern.endswith("|") or "(|" in pattern or "|)" in pattern:
        return "has an empty alternative, which would match everything"
    try:
        rx = re.compile(pattern, re.I)
    except re.error as e:
        return f"does not compile ({e})"
    if rx.search("") or rx.search("a") or rx.search(" "):
        return "matches empty or trivial text"
    longest_literal = max((len(x) for x in re.split(r"[|()?]", pattern)), default=0)
    if longest_literal < 6:
        return "is too short to be specific"
    for msg in benign:
        if rx.search(msg):
            return f"fires on an ordinary message: {msg[:60]!r}"
    return None
