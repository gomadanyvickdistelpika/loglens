# LogLens - targeted VMware log analysis

> **Unofficial project.** LogLens is an independent, community tool. It is not affiliated with, endorsed by or supported by Broadcom or VMware.
> KB links come from public search results (titles and URLs only; article text was not read) and may be out of date. Always verify a finding against the raw log and the vendor's own documentation.
> Case templates are anonymised, synthetic scenarios (invented hosts, 192.0.2.x addresses); no real customer logs or data are included. Never upload customer logs to a tool you do not control.


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

## Broadcom KB research

Every finding carries a **Broadcom KB research** block: the matching knowledge-base articles (links), the documented cause and the
resolution steps. If nothing in the library matches, the report says so plainly ("No Broadcom KB found ...") and gives a search phrase.

- Source: `lvx/kb_library.json`, a dated **snapshot** of research on knowledge.broadcom.com (summaries of search results, not article text).
  It is **not a live search**. Open each article and confirm it applies to your exact build before acting.
- Entries can be narrowed by a regex on the log text so only relevant articles show; unmatched generic messages and report items
  without a KB number are reported as "no KB found".
- Add or override entries with your own file: `LVX_KB_FILE=/path/extra.json` (same schema; a broken file is ignored).
- Regenerate the shipped library with `python tools/build_kb_library.py` after editing it.

## Resolved-case templates

`lvx/case_templates.json` holds 26 **anonymised templates** distilled from 31 resolved support-case reports: the symptom in generic wording,
a **synthetic** log excerpt, the detections LogLens must raise, the cause and resolution the case documented, and the Broadcom KB links the case cited.
When a finding matches a template, its resolution and KB links appear in the finding's "Broadcom KB research" block, labelled
*from a resolved support case (anonymised)*. If the case documented no resolution or cited no KB, the template says so.

- `python -m lvx templates list` / `show CT-13` / `build CT-13 OUT_DIR` (writes a synthetic bundle + `.tgz` you can upload to the UI).
- Log lines are synthetic: `case` = wording taken from the case's own excerpt (anonymised), `typical` = written for the template. Templates marked `no-log`
  have no bundle because the case contained no log evidence.
- **No customer data**: no names, case numbers, real hostnames/IPs or emails. `tests/test_templates.py` enforces this (hash-only denylist in `tests/privacy_denylist.sha256`).
- Regenerate with `python tools/build_case_templates.py`; run the accuracy check with `python tests/templates_accuracy.py`.

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
- KB research is a research snapshot (see above), not a live Broadcom search; resolutions are summaries and must be confirmed in the article.
* Signature rules are my own generic patterns, not Broadcom's. KB numbers are shown only where they came from your
  sample reports (80867, 78543); other findings carry a KB *search phrase* instead of a guess.
* Accuracy numbers come from synthetic bundles; validate on real, sanitised bundles and send me misses.
* Syslog-style lines without a year assume the year of the newest log. Naive times are UTC.
