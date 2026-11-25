# Live mode: follow a server over SSH (read-only)

Instead of collecting a support bundle by hand, LogLens can connect to an **ESXi host, vCenter appliance (VCSA), XCP-ng host or Xen Orchestra** over SSH, mirror the logs, and re-analyse them every few seconds. New findings are announced as they appear. Everything else in LogLens (log viewer, "show log context", Confirm / Reject / Unsure, exports) works on the live data.

## Start it

```powershell
# web UI (adds a "Live: connect over SSH" panel)
python -m lvx serve --live --open

# or in the terminal, no browser
python -m lvx live root@esx01.lab.example --product esxi --key C:\Users\me\.ssh\id_ed25519
python -m lvx live admin@vcsa.lab.example --product vcsa --password        # prompts, kept in memory only
python -m lvx live root@xcp01 --product xcpng --issue "VM db02 will not start"
```

Products: `esxi`, `vcsa`, `xcpng`, `xo`. Press Ctrl+C to stop. `--save DIR` keeps the mirrored logs (a normal bundle layout you can re-open later).

## What it does on the server

* Opens **one** `ssh` connection using the system OpenSSH client (built in to Windows 10/11, macOS and Linux) and runs a small `sh` loop through it.
* Reads logs from a fixed list per product (for example `/var/run/log/vmkernel.log` on ESXi, `/var/log/vmware/vpxd/vpxd.log` on VCSA, `/var/log/SMlog` on XCP-ng, `journalctl -u xo-server` on XO) by byte offset, so each poll transfers only new bytes. Rotation is detected and the old mirror is archived as `*.prev`.
* Takes a few read-only snapshots at connect time: `df -h`, `uptime`, and product info such as `esxcli system version get`, `service-control --status --all`, `xe sr-list`. `df -h` feeds the "filesystem almost full" early warning.
* It **cannot** run anything else. There is no command box. Extra log files you add must be absolute paths under `/var/log`, `/var/run/log`, `/storage/log` or `/scratch/log`; paths with `..`, spaces or shell characters are rejected, and every value is shell-quoted.

## Security model

| Concern | How it is handled |
|---|---|
| Passwords | Never stored. With `--password` / the password field the value lives in memory and is passed to `ssh` only through `SSH_ASKPASS` in the child process environment. Prefer keys or ssh-agent. |
| Saved connections | `~/.lvx/profiles.json` (or `$LVX_HOME`) holds host, user, key *path*, product. No secrets. |
| Host keys | Default is trust-on-first-use (`StrictHostKeyChecking=accept-new`): a changed key is rejected. Choose **Strict** to require the host already be in `known_hosts`. |
| Who can use it | Live is off unless you start with `--live` / `LVX_LIVE=1`. On any non-localhost address it refuses to start without `LVX_TOKEN`, because the web server would otherwise hand your SSH access to the network. |
| Customer data | Mirrored logs live in a temp folder removed on exit (unless `--save`). Use **Mask emails, secrets, links and IPs** when downloading reports. |

## Preparing the target

* **ESXi:** enable SSH (Host > Manage > Services, or DCUI). Key auth: put the public key in `/etc/ssh/keys-root/authorized_keys`.
* **VCSA:** SSH must be enabled and the root/admin **shell must be bash**, not `appliancesh` (`shell.set --enabled true`, then `chsh -s /bin/bash root`). `service-control` is only used for the read-only status snapshot.
* **XCP-ng / XOA:** normal SSH. For XO from sources, `journalctl` must be readable by the SSH user.

## Limits and honesty

* Verified automatically with a real local shell (byte-exact incremental reads, partial lines, rotation, reconnect framing, the full HTTP flow) and against the real OpenSSH client for failure handling. **Not yet exercised against a live ESXi, VCSA or XCP-ng host**; ESXi uses BusyBox `sh`, so report any difference you see.
* Password login relies on `SSH_ASKPASS`; on some Windows/OpenSSH builds key or agent login is more reliable.
* A mirrored file stops growing at 200 MB; the UI shows a warning when that happens.
