# Vates Toolbox and VTLog

The VMware build of LogLens understands two external reports, **GSS Toolbox** (health modules) and **TDLog** (signature matches and certificates). Neither exists for XCP-ng or Xen Orchestra, so the Vates build has its own counterparts, built into LogLens and needing no extra software on the server:

| VMware | Vates | What it answers |
|---|---|---|
| GSS Toolbox | **Vates Toolbox** | "Is anything unhealthy right now?" Point-in-time modules with an alert level, a resolution and the related rule |
| TDLog | **VTLog** | "When did each known problem pattern first appear in this bundle, and how often?" Signature history over the whole bundle, plus certificates |

In a Vates-only build (`LVX_PACKS=vates`, the default of `loglens-vates`) the tab is called **Vates Toolbox / VTLog** and the GSS/TDLog wording disappears.

## Vates Toolbox

Input: the read-only command output a bundle already contains, `<node>/commands/<name>.txt`, or the same commands collected live over SSH (live mode refreshes them every 5 minutes). One report per XCP-ng host or Xen Orchestra appliance; pool-wide modules (SR space, HA, version drift) are reported once.

| Module | File it reads | critical / warning |
|---|---|---|
| `filesystem` | `df_-h` | >= 95% / >= 85% on any real filesystem (`/`, `/var/log`, XO data volume) |
| `memory` | `free_-m` | < 5% available or swap > 90% / < 10% or swap > 50% |
| `sr_space` | `xe_sr-list` | SR >= 95% / >= 85% (keep ~30% free on thick LVM) |
| `ha_config` | `xe_pool-list`, `xe_host-list` | - / HA enabled on a pool of fewer than 3 hosts |
| `version_consistency` | `xe_host-list` | - / hosts on different XCP-ng versions |
| `multipath` | `multipath_-ll` | failed/faulty path / a map with a single path |
| `time_sync` | `chronyc_tracking` | not synchronised / offset > 1 s |
| `toolstack` | `systemctl_is-active_xapi` (`..._xo-server`) | service not active / - |
| `certificate` | `openssl_x509_enddate` | expired or < 14 days / < 30 days |

A check whose command is missing or printed an error (`chronyc: not found`) gives **no verdict**, never a false alarm. Each module carries the LogLens rule it relates to, so the Vates KB research is attached to it in the report.

```powershell
python -m lvx toolbox examples/virtual-estate/BW-05-dom0-oom.tgz --time 2026-11-16T05:40:00Z -o vates-toolbox.txt
```

writes a plain-text report (the GSS Toolbox style: one `Matched Module:` block per check) that you can attach to a ticket. A file named `vates-toolbox*.txt` inside a bundle is parsed back and shown in the tab.

## VTLog

Scans **every** log line of the bundle, ignoring the incident window, against the Vates rule signatures. Per signature it shows matches, days with hits, first and last time, the main file, sample lines, and whether a hit falls inside the incident window. A signature that fired only before the window is a precursor (or stale) and is greyed out; the example bundles plant a transient disk I/O error 28 hours before each incident to show this. The certificates table lists the TLS expiry state of each host and appliance.

## Where it appears
* **Web UI:** the *Vates Toolbox / VTLog* tab, and a "From Vates Toolbox / VTLog reports" list under the findings.
* **Reports:** the Markdown / HTML / JSON exports gain a "Vates Toolbox / VTLog findings" section.
* **Live mode:** `Connect and follow` on an XCP-ng host or XO appliance collects the toolbox commands (fixed, read-only list) and keeps the Toolbox current.

## Names
The display names are constants (`BRAND` in `lvx/vtoolbox.py` and `lvx/vtlog.py`, `BRAND` in `lvx/web/index.html`); change them in those three places to rename the tools.
