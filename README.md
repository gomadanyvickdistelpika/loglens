# LogLens - targeted VMware log analysis

Same job as the Lumberjack Log Viewer + TDLog + GSS Toolbox workflow, but **driven by the customer's
issue and timestamp**: everything outside the incident window is treated as noise and findings are
ranked by how well they fit the reported symptom.

One engine (`lvx/`, Python standard library only), three ways to run it:

| Where | How |
|---|---|
| Windows (Python installed) | `run.bat` |
| Windows single `.exe` | `powershell -ExecutionPolicy Bypass -File build_windows.ps1` -> `dist\LogLens.exe` |
| Linux | `./run.sh`  or  `python3 -m lvx serve --host 0.0.0.0` |
| Docker / cloud | `docker build -t loglens .` then `docker run -p 8765:8765 -v /bundles:/data:ro -e LVX_ROOTS=/data loglens` |
| CLI / automation | `python -m lvx analyze bundle.tgz --issue "..." --time 2026-09-27T14:30:00Z --format html -o report.html` |

## Workflow
1. **Open** a bundle: drag in `.zip/.tgz/.tar.gz` (nested archives, rotated `.gz` logs fine), a log file, a
   GSS Toolbox `.txt` or TDLog `.txt/.pdf`, or type a server-side path.
2. **Describe** the symptom and the **incident time** (UTC unless you give a zone). Choose look-back / look-ahead.
   No time given -> newest operational log timestamp is the anchor and the last 10 days are examined.
3. **Analyze** -> ranked findings, each with evidence lines (+context), first/last seen, occurrence sparkline,
   next step, KB search phrase, link into the viewer at the exact line.
4. Tabs: **Timeline** (errors/warnings per bucket, incident marker, event sequence), **Log viewer** (line numbers,
   level colouring, text/regex search with next/prev, case, level filter, incident-window-only, jump to line),
   **Toolbox / TDLog** (parsed reports; entries whose events/dates fall outside the window are greyed as *stale*),
   **Run info**. Export Markdown / HTML / JSON.

## How the noise is removed
* Time window filter (before/after the incident) - out-of-window lines are only counted, never ranked.
* Level detection; benign phrases (`errors: 0`, `successfully`, ...) ignored.
* Messages normalised (ids, IPs, numbers) and clustered, so 10 000 repeats = one finding.
* **Chronic** patterns spread evenly across the window are demoted; always-on **advisories** are listed separately.
* Ranking = rule severity + issue-topic match + keyword overlap + closeness to the incident time + volume.

## Security notes
Binds to `127.0.0.1` by default. For shared/cloud use set `LVX_TOKEN` (bearer token), `LVX_ROOTS` (folders
the server may open) or `LVX_ALLOW_OPEN=0`, and put it behind HTTPS. Archives are unpacked to a temp dir
with path-traversal/symlink protection and size caps, and deleted when the bundle is closed.
Nothing is sent to any external service.

## Tests
`python tests/test_all.py` (unit + HTTP API + your real Toolbox/TDLog samples when present) and
`python tests/accuracy.py` (synthetic bundles with planted incidents, decoys outside the window and noise,
across dir/zip/tgz/nested-archive formats; passes at >= 95%).

## Honest limits
* Signature rules are my own generic patterns, not Broadcom's. KB numbers are shown only where they came from your
  sample reports (80867, 78543); other findings carry a KB *search phrase* instead of a guess.
* Accuracy numbers come from synthetic bundles; validate on real, sanitised bundles and send me misses.
* Syslog-style lines without a year assume the year of the newest log. Naive times are UTC.
