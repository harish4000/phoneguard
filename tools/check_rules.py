#!/usr/bin/env python3
"""Build check: the built-in scam rules must not raise an alert on ordinary messages.

Reads the rule table straight out of the app source, scores every line of data/benign-messages.txt,
and fails the build if any reaches the alert threshold. It also re-validates the AI-written patterns.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import rulecheck  # noqa: E402

ALERT_AT = 60


def static_rules():
    src = open(os.path.join(ROOT, "app/src/main/java/com/harish/phoneguard/Scam.kt"), encoding="utf-8").read()
    out = []
    for pat, pts, reason in re.findall(r'Triple\("((?:[^"\\]|\\.)*)", (\d+), "([^"]+)"\)', src):
        out.append((re.compile(pat.replace("\\\\", "\\"), re.I), int(pts), reason))
    return out


def lines_of(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return [x.rstrip("\n") for x in f if x.strip() and not x.startswith("#")]


def main():
    rules = static_rules()
    if len(rules) < 8:
        sys.exit("Could not read the rule table from Scam.kt")
    benign = lines_of("data/benign-messages.txt")
    worst, failed = 0, 0
    for msg in benign:
        score = sum(pts for rx, pts, _ in rules if rx.search(msg))
        worst = max(worst, score)
        if score >= ALERT_AT:
            failed += 1
            print(f"FALSE ALARM ({score}): {msg}")
    bad_ai = 0
    for line in lines_of("data/scam-rules.txt"):
        p = line.split("\t")
        why = rulecheck.problem(p[2], benign) if len(p) >= 4 else "malformed line"
        if why:
            bad_ai += 1
            print(f"AI pattern will be dropped: {line[:80]} -> {why}")
    print(f"{len(rules)} built-in rules, {len(benign)} ordinary messages, highest score {worst}, {failed} false alarms, {bad_ai} AI patterns dropped")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
