# vlan-auditor

Audit Cisco IOS switch configurations for VLAN best-practice violations.
Point it at one or more running-config files and get a clear,
prioritized report of what to fix — before an attacker or an outage finds it first.

## Features

- Parses Cisco IOS running-configs: VLAN database, per-interface switchport mode,
  access VLAN, trunk allowed VLANs, and trunk native VLAN
- 5 audit checks, each with a severity rating (HIGH / MEDIUM / LOW):

| Check | Severity | What it finds |
|---|---|---|
| `ACCESS_VLAN_1` | HIGH | Access port in VLAN 1 (explicit or by default) — VLAN hopping risk |
| `NATIVE_VLAN_1` | MEDIUM | Trunk with native VLAN 1 (explicit or default) — use a dedicated unused VLAN |
| `TRUNK_ALLOW_ALL` | MEDIUM | Trunk carrying all VLANs 1–4094 (no pruning configured) |
| `ACCESS_NO_EXPLICIT_MODE` | MEDIUM | `switchport access vlan` set without `switchport mode access` (DTP risk) |
| `UNUSED_VLAN` | LOW | VLAN defined in the database but not used on any port |

- Human-readable text report on stdout, plus optional JSON report (`--json`)
- Handles real-world syntax: `allowed vlan add`, `except`, ranges (`10-20`),
  voice VLANs, SVIs, shutdown ports, and routed (`no switchport`) interfaces
- Pure Python standard library — no dependencies

## Usage

```bash
# Audit one or more configs
python3 vlan_audit.py samples/core-sw.cfg samples/access-sw.cfg

# Also write a JSON report
python3 vlan_audit.py samples/core-sw.cfg --json report.json
```

## Example output

```
$ python3 vlan_audit.py samples/core-sw.cfg samples/access-sw.cfg
VLAN Audit Report
============================================================

Device: CORE-SW  (source: samples/core-sw.cfg)
  Interfaces audited : 4 (trunk: 2, access: 2)
  VLANs defined      : 5

Device: ACCESS-SW  (source: samples/access-sw.cfg)
  Interfaces audited : 5 (trunk: 1, access: 4)
  VLANs defined      : 4

Findings: 8
------------------------------------------------------------
[HIGH] ACCESS_VLAN_1
    CORE-SW / GigabitEthernet0/3: Access port explicitly assigned to VLAN 1 — move user ports off the default VLAN 1.
[MEDIUM] NATIVE_VLAN_1
    CORE-SW / GigabitEthernet0/1: Trunk native VLAN is 1 (explicitly set) — use a dedicated unused VLAN instead.
[MEDIUM] TRUNK_ALLOW_ALL
    CORE-SW / GigabitEthernet0/1: No 'switchport trunk allowed vlan' list — trunk carries all VLANs 1-4094. Prune to only required VLANs.
[LOW] UNUSED_VLAN
    CORE-SW / VLAN 99: VLAN 99 (Unused-VLAN) is defined but not used on any port — remove it to keep the VLAN database clean.
[HIGH] ACCESS_VLAN_1
    ACCESS-SW / FastEthernet0/1: Access port defaults to VLAN 1 (no 'switchport access vlan' configured) — move user ports off the default VLAN 1.
[MEDIUM] ACCESS_NO_EXPLICIT_MODE
    ACCESS-SW / FastEthernet0/2: Has 'switchport access vlan' but no 'switchport mode access' — port relies on DTP negotiation; set the mode explicitly.
[MEDIUM] NATIVE_VLAN_1
    ACCESS-SW / GigabitEthernet0/1: Trunk native VLAN is 1 (defaults (no 'switchport trunk native vlan' configured)) — use a dedicated unused VLAN instead.
[LOW] UNUSED_VLAN
    ACCESS-SW / VLAN 40: VLAN 40 (Old-VLAN) is defined but not used on any port — remove it to keep the VLAN database clean.
------------------------------------------------------------
Summary: 2 HIGH, 4 MEDIUM, 2 LOW
```

## Sample configs

The `samples/` directory contains two realistic Cisco 2960 configs
(`core-sw.cfg`, `access-sw.cfg`) that deliberately demonstrate every check,
so you can see the full report on the first run.

## Requirements

- Python 3.8+

## How it works

1. **Parse** — walks each config, extracting the VLAN database
   (`vlan <id>` / `name`) and every `interface` block's switchport settings.
2. **Audit** — applies the 5 checks, tracking which VLANs are actually
   referenced (access, voice, native, trunk-allowed, SVI).
3. **Report** — prints findings sorted by severity, and optionally
   writes structured JSON for automation pipelines.

## License

MIT
