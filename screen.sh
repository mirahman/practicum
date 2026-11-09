#!/bin/bash
# Usage: ./screen.sh <repo-url>
name=$(basename "$1")
git clone -q --filter=blob:none --depth 1 "$1" /tmp/screen-$name 2>/dev/null
cd /tmp/screen-$name || exit 1
files=$(git ls-files '*.go' | wc -l)
semgrep scan --config=p/default --pro --sarif -o /tmp/screen-$name.sarif \
  --metrics=off --exclude='ui/' --exclude='*_test.go' . 2>/dev/null
python - "$name" "$files" <<'PY'
import json, sys, collections
name, files = sys.argv[1], sys.argv[2]
d = json.load(open(f'/tmp/screen-{name}.sarif'))
taint = ('taint','sqli','injection','ssrf','traversal','xss','command')
c = collections.Counter()
for r in d["runs"]:
    for x in r["results"]:
        if not x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(".go"):
            continue
        rid = x["ruleId"].lower()
        c['taint' if any(t in rid for t in taint) else 'pattern'] += 1
print(f"{name:20s} go_files={files:>6}  taint={c['taint']:>4}  pattern={c['pattern']:>4}")
PY
