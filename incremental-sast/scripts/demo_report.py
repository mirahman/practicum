#!/usr/bin/env python3
"""Write a one-page review-queue viewer, from func_filter.py output.

  python scripts/demo_report.py --out demo.html \
      --tab gitea,gitea_func_result.json,e21c37703e,~/codes/practicum/corpus/gitea \
      --tab traefik,traefik_func_result.json,0331801c72,~/codes/practicum/corpus/traefik

Each --tab is NAME,RESULT_JSON,COMMIT[,REPO]. One tab per project, shown at the top.
The old single form (--result, --commit, --repo) still works and makes a page with no tabs.

Each tab shows, for its commit:
  - the queue at four stages (full diff scan, filter only, differencing only, both)
  - each finding with the reason it stays or goes (changed function, linked, unconnected)
  - a switch between the full diff scan and the baseline-differenced scan
  - a switch to show the removed findings
Nothing is recomputed. It only reads the JSON that func_filter.py wrote.
REPO is optional; with it, the tab also shows the commit title and files changed.
"""
import argparse, html, json, os, subprocess
from collections import defaultdict
from pathlib import Path

REASON = {
    "changed_function": ("In a function the commit changes", "ok"),
    "linked_1": ("Within one call of a changed function", "ok"),
    "linked_2": ("Within two calls of a changed function", "ok"),
    "no_function": ("Outside any function (always kept)", "keep"),
    "unconnected": ("No link to the commit's changes (removed)", "gone"),
}


def git(repo, *a):
    r = subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    return r.stdout.strip()


def build(idx, name, result, commit, repo, view):
    recs = [r for r in json.load(open(result)) if r["commit"].startswith(commit)]
    if not recs:
        raise SystemExit("no findings for commit %s in %s" % (commit, result))
    sha = recs[0]["commit"]
    rows = []
    for r in recs:
        lab = r[view]
        rows.append(dict(file=r["file"], line=r["line"], rule=r["rule"],
                         function=str(r.get("function") or ""), label=lab,
                         kept=lab != "unconnected", reported=bool(r["reported"]),
                         artifact=bool(r["artifact"])))
    n = (len(rows), sum(r["kept"] for r in rows), sum(r["reported"] for r in rows),
         sum(r["reported"] and r["kept"] for r in rows))
    title, nfiles = "", ""
    if repo:
        repo = os.path.expanduser(repo)
        title = git(repo, "show", "-s", "--format=%s", sha)
        names = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha).splitlines()
        nfiles = "%d files changed" % len(names)

    items = [(n[0], "full diff scan"), (n[1], "function filter only"),
             (n[2], "baseline differencing only"), (n[3], "differencing, then filter")]
    cards = "".join('<div class="card"><div class="big">%d</div><div>%s</div></div>' % (c, html.escape(t))
                    for c, t in items)

    by = defaultdict(list)
    for r in rows:
        by[r["file"]].append(r)
    trs = []
    for f in sorted(by):
        for r in sorted(by[f], key=lambda x: x["line"]):
            text, cls = REASON.get(r["label"], (r["label"], "keep"))
            art = ' <span class="tag art">scope artifact</span>' if r["artifact"] else ""
            trs.append('<tr class="%s" data-kept="%d" data-rep="%d"><td>%s:%s</td><td>%s</td>'
                       '<td class="fn">%s</td><td><span class="tag %s">%s</span>%s</td></tr>' % (
                           "kept" if r["kept"] else "removed", r["kept"], r["reported"],
                           html.escape(r["file"]), r["line"], html.escape(r["rule"]),
                           html.escape(r["function"]), cls, html.escape(text), art))
    sub = " | ".join(x for x in (title, nfiles, "view: " + view) if x)
    pane = ('<section class="pane" id="p%d" data-name="%s">'
            '<h1>%s: review queue for commit %s</h1><div class="sub">%s</div>'
            '<div class="cards">%s</div>'
            '<div class="bar"><span>Start from:</span>'
            '<button class="b_full on">Full diff scan</button>'
            '<button class="b_diff">After baseline differencing</button>'
            '<span style="width:16px"></span>'
            '<button class="b_removed">Show removed findings</button>'
            '<span class="count"></span></div>'
            '<table><thead><tr><th>Where</th><th>Rule</th><th>Function</th><th>Why it stays or goes</th></tr></thead>'
            '<tbody>%s</tbody></table></section>') % (
        idx, html.escape(name), html.escape(name), html.escape(sha[:12]), html.escape(sub), cards, "\n".join(trs))
    return pane, n


CSS = """
:root{--bg:#fff;--fg:#1f2937;--mut:#5b6577;--card:#f5f7fa;--navy:#1b2a4e;--blue:#2f5bd3;--red:#b03a2e;--line:#e5e7eb;--ok:#e3f1e6;--okf:#1f6b36;--gone:#fbe9e7;--gonef:#8a2f23;--keep:#fff3d6;--keepf:#7a5a05}
@media (prefers-color-scheme:dark){:root{--bg:#10151f;--fg:#e6e9ef;--mut:#9aa4b8;--card:#1a2230;--navy:#c9d3ea;--blue:#7fa2ff;--red:#ff8a7a;--line:#2a3447;--ok:#183a24;--okf:#8be0a4;--gone:#3d1d19;--gonef:#ffb3a8;--keep:#3a2f10;--keepf:#ffd77a}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 Calibri,Segoe UI,Arial,sans-serif}
.wrap{max-width:1150px;margin:0 auto;padding:24px 16px 48px}
.tabs{display:flex;gap:6px;border-bottom:2px solid var(--line);margin-bottom:18px}
.tabs button{border:1px solid var(--line);border-bottom:none;border-radius:8px 8px 0 0;padding:10px 22px;font-size:17px;font-weight:600;background:var(--card);color:var(--mut)}
.tabs button.on{background:var(--blue);color:#fff;border-color:var(--blue)}
h1{font:700 26px Georgia,serif;color:var(--navy);margin:0 0 4px}
.sub{color:var(--mut);margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0 18px}
.card{background:var(--card);border-radius:10px;padding:14px;text-align:center;color:var(--mut)}
.big{font:700 40px Georgia,serif;color:var(--navy)}
.card:nth-child(4) .big{color:var(--red)}
.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:10px 0}
button{font:inherit;padding:8px 14px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;cursor:pointer}
.bar button.on{background:var(--blue);color:#fff;border-color:var(--blue)}
table{width:100%;border-collapse:collapse;font-size:14.5px}
th{text-align:left;color:var(--mut);font-weight:600;border-bottom:2px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}
.fn{color:var(--mut);font-size:13px}
.tag{display:inline-block;border-radius:6px;padding:1px 8px;font-size:13px}
.tag.ok{background:var(--ok);color:var(--okf)}.tag.gone{background:var(--gone);color:var(--gonef)}.tag.keep{background:var(--keep);color:var(--keepf)}
.tag.art{background:var(--red);color:#fff;margin-left:6px}
tr.removed td{opacity:.8}
.count{color:var(--mut)}
.pane{display:none}.pane.show{display:block}
@media (max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}}
"""

JS = """
function setup(p){
  var mode="full", showRemoved=false;
  function apply(){
    var kept=0, shown=0;
    p.querySelectorAll("tbody tr").forEach(function(tr){
      var inQ = mode==="full" || tr.getAttribute("data-rep")==="1";
      var isK = tr.getAttribute("data-kept")==="1";
      var show = inQ && (isK || showRemoved);
      tr.style.display = show ? "" : "none";
      if(inQ && isK) kept++;
      if(show) shown++;
    });
    p.querySelector(".count").textContent = kept + " findings in the queue" + (showRemoved ? " (" + shown + " rows shown)" : "");
    p.querySelector(".b_full").className = "b_full" + (mode==="full" ? " on" : "");
    p.querySelector(".b_diff").className = "b_diff" + (mode==="diff" ? " on" : "");
    p.querySelector(".b_removed").className = "b_removed" + (showRemoved ? " on" : "");
  }
  p.querySelector(".b_full").onclick=function(){mode="full";apply();};
  p.querySelector(".b_diff").onclick=function(){mode="diff";apply();};
  p.querySelector(".b_removed").onclick=function(){showRemoved=!showRemoved;apply();};
  apply();
}
var panes=document.querySelectorAll(".pane"), tabs=document.querySelectorAll(".tabs button");
panes.forEach(setup);
function show(i){
  panes.forEach(function(p,j){p.className="pane"+(j===i?" show":"");});
  tabs.forEach(function(t,j){t.className=j===i?"on":"";});
}
tabs.forEach(function(t,i){t.onclick=function(){show(i);};});
show(0);
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--result")
    ap.add_argument("--commit")
    ap.add_argument("--tab", action="append", default=[], help="NAME,RESULT_JSON,COMMIT[,REPO]")
    ap.add_argument("--view", choices=["strict", "cautious"], default="cautious")
    ap.add_argument("--repo", default=None)
    ap.add_argument("--out", default="demo_report.html")
    a = ap.parse_args()

    specs = []
    for t in a.tab:
        p = t.split(",")
        if len(p) not in (3, 4):
            raise SystemExit("--tab needs NAME,RESULT_JSON,COMMIT[,REPO]: " + t)
        specs.append((p[0], p[1], p[2], p[3] if len(p) == 4 else None))
    if not specs:
        if not (a.result and a.commit):
            raise SystemExit("give --tab (one per project), or --result and --commit")
        specs.append((a.commit[:12], a.result, a.commit, a.repo))

    panes, counts = [], []
    for i, (name, res, com, repo) in enumerate(specs):
        pane, n = build(i, name, res, com, repo, a.view)
        panes.append(pane)
        counts.append((name, n))
    tabbar = ""
    if len(specs) > 1:
        tabbar = '<div class="tabs">' + "".join("<button>%s</button>" % html.escape(s[0]) for s in specs) + "</div>"
    else:
        tabbar = '<div class="tabs" style="display:none"><button></button></div>'
    page = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Review queue demo</title><style>%s</style></head><body><div class="wrap">%s%s</div>'
            '<script>%s</script></body></html>') % (CSS, tabbar, "\n".join(panes), JS)
    Path(a.out).write_text(page, encoding="utf-8")
    for name, n in counts:
        print("%s: full %d, filter %d, differenced %d, both %d" % (name, *n))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
