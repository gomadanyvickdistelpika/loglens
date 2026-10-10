# Test bundles

Synthetic bundles for trying LogLens (invented hostnames, 192.0.2.x addresses; no real customer data).

1. `python -m lvx serve` and open the printed address.
2. Upload a bundle from `vmware/`, then compare with `reference-reports/`.

| Bundle | Scenario |
|---|---|
| 1-vcenter-503-expired-cert | vCenter 503 after reboot, expired certificate (scenario from public KB summaries) |
| 2-esxi-vmxnet3-heap | ESXi vmxnet3 heap admission failure after power outage |
| 3-vm-snapshots-datastore-full | VM down, snapshots filled the datastore |
| 4-ha-agent-install-fail | HA agent cannot be installed (missing components) |

More scenarios: `python -m lvx templates list` and `python -m lvx templates build CT-xx OUT_DIR`.
