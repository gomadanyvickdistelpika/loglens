# LogLens - targeted VMware and Vates (XCP-ng / Xen Orchestra) log analysis

> **Unofficial project.** LogLens is an independent, community tool. It is not affiliated with, endorsed by or supported by Broadcom, VMware or Vates. XCP-ng and Xen Orchestra are products/trademarks of their owners.
> KB links come from public search results (titles and URLs only; article text was not read) and may be out of date. Always verify a finding against the raw log and the vendor's own documentation.

**Two rule packs, one engine.** `vmware` (ESXi, vCenter, SDDC: 63 rules, Broadcom KB, 49 case templates) and `vates` (XCP-ng, Xen Orchestra: 25 rules, public Vates/XCP-ng pages, 19 scenarios). The product of each file is detected automatically, so a mixed bundle works. `LVX_PACKS=vates` (or `vmware`) gives a single-family build; this replaces the separate `loglens-vates` project.
The VMware pack reads GSS Toolbox and TDLog reports; the Vates pack has its own counterparts, **Vates Toolbox** (health modules from `commands/` output) and **VTLog** (signature history and certificates), built in - see [docs/VATES_TOOLBOX.md](docs/VATES_TOOLBOX.md).
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

## Try it now: six virtual client bundles + live replay
[`examples/virtual-estate/`](examples/virtual-estate/CASES.md) holds six full-size XCP-ng + Xen Orchestra bundles for a fictional client (2 hosts, 1 orchestrator, SAN, NAS, 6 VMs; ~35 files each), each with a different fault: SR full, HA self-fence after a bond failure, dom0 `/var/log` full, NFS outage, dom0 OOM, XO appliance disk full. `CASES.md` lists the ticket, the incident time, what LogLens must rank first and the `grep` commands that confirm the cause by hand. Rebuild with `python tools/build_virtual_estate.py OUT_DIR`.
To watch **live mode** without a server: `python tools/live_demo.py BW-03` (replays a case into a local "remote host" that the Live panel follows).
The `loglens-vates` repo is a Vates-default build of this code: `python tools/sync_variants.py ../loglens-vates`.

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

## Live mode, action plan and masked exports
* **Live over SSH** (ESXi, vCenter appliance, XCP-ng, Xen Orchestra): `python -m lvx serve --live` or `python -m lvx live root@host --product esxi`. Read-only, key/agent auth, nothing stored. See [docs/LIVE.md](docs/LIVE.md).
* **Action plan and drafts** (merged from the vmware-case-agent project): every report ends with safe READ-ONLY checks, RISKY / DISRUPTIVE steps marked *approval required*, a rollback plan, a KB applicability gate, missing evidence, and customer-ready and internal-note drafts that never claim a root cause until a reviewer confirms one.
* **Masked exports:** `--redact` on the CLI, `?redact=1` on report URLs, or the checkbox in the UI masks emails, phone numbers, secrets, private links and IPs (official KB links, timestamps and evidence are kept). `--redact-term NAME` masks customer, host or VM names.

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

## Verify findings against the raw log

Every finding in the web UI has **Confirm / Reject / Unsure** buttons, an optional note, and **Show log context (+-4 lines)**, which pulls the matching lines straight from the bundle file. Verdicts are kept in your browser and included in the Markdown/HTML/JSON exports ("Reviewer verdict"). API: `GET /api/evidence?job=&finding=&ctx=`, `POST /api/jobs/<id>/verdicts`.
