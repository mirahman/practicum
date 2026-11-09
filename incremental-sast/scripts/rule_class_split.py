#!/usr/bin/env python3
"""Break the removable/kept split down by rule class (taint vs pattern).
Reads the *_func_result.json files already written by func_filter.py.
No rerun needed.

Usage:
  python scripts/rule_class_split.py gitea_func_result.json traefik_func_result.json
"""
import json, sys, collections

TAINT_HINTS = ("taint", "sqli", "injection", "ssrf", "traversal", "xss",
              "command", "redirect")


def rule_class(rule_id):
    r = rule_id.lower()
    return "taint" if any(h in r for h in TAINT_HINTS) else "pattern"


def main():
    for path in sys.argv[1:]:
        records = json.load(open(path))
        by_class = collections.defaultdict(lambda: collections.Counter())
        for r in records:
            cls = rule_class(r["rule"])
            by_class[cls][r["cautious"]] += 1
            by_class[cls]["total"] += 1

        print("=" * 60)
        print(path)
        print("=" * 60)
        for cls in ("taint", "pattern"):
            c = by_class[cls]
            n = c["total"]
            if n == 0:
                print("  %-8s 0 findings" % cls)
                continue
            rem = c["unconnected"]
            print("  %-8s %4d findings, %4d removable (%.1f%%)" % (cls, n, rem, 100.0 * rem / n))
            for k in ("changed_function", "linked_1", "linked_2", "unconnected", "no_function"):
                if c[k]:
                    print("      %-18s %4d" % (k, c[k]))
        print()


if __name__ == "__main__":
    main()
