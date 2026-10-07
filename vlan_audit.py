#!/usr/bin/env python3
"""
vlan-auditor
============
Audit Cisco IOS switch configurations for VLAN best-practice violations.

Usage:
    python3 vlan_audit.py config1.txt config2.txt
    python3 vlan_audit.py config1.txt --json report.json

Checks performed on every switchport:
    1. ACCESS_VLAN_1       (HIGH)   Access port in VLAN 1 (security risk)
    2. NATIVE_VLAN_1       (MEDIUM) Trunk with native VLAN 1
    3. TRUNK_ALLOW_ALL     (MEDIUM) Trunk allowing all VLANs 1-4094 (not pruned)
    4. UNUSED_VLAN         (LOW)    VLAN defined but not used on any port
    5. ACCESS_NO_EXPLICIT_MODE (MEDIUM) Access VLAN set without
                                       'switchport mode access' (DTP risk)

Only the Python standard library is required (Python 3.8+).
"""

import argparse
import json
import re
import sys
from pathlib import Path

ALL_VLANS = set(range(1, 4095))
IGNORED_VLANS = {1, 1002, 1003, 1004, 1005}  # default + legacy FDDI/Token Ring

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def parse_vlan_list(text):
    """Parse Cisco VLAN list syntax ('10,20-25,30', 'none') into a set of ints."""
    vlans = set()
    for part in text.split(","):
        part = part.strip()
        if not part or part.lower() == "none":
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            vlans.update(range(int(start), int(end) + 1))
        else:
            vlans.add(int(part))
    return vlans


class Interface:
    """A parsed switchport (or SVI / routed port) configuration block."""

    def __init__(self, name):
        self.name = name
        self.mode = None            # 'access', 'trunk', 'dynamic', or None
        self.access_vlan = None     # int or None
        self.voice_vlan = None      # int or None
        self.native_vlan = None     # int or None (trunks)
        self.allowed_vlans = None   # set or None (None = not configured -> all)
        self.routed = False         # 'no switchport'
        self.shutdown = False
        self.has_switchport_cfg = False

    @property
    def is_svi(self):
        return self.name.lower().startswith("vlan")

    @property
    def is_trunk(self):
        return self.mode == "trunk" and not self.routed


def _parse_interface_line(iface, line):
    """Parse one indented line inside an interface block."""
    if not line.startswith("switchport") and line not in ("shutdown", "no shutdown"):
        return

    iface.has_switchport_cfg = iface.has_switchport_cfg or line.startswith("switchport")

    match = re.match(r"^switchport mode\s+(\S+)", line)
    if match:
        mode = match.group(1)
        if "trunk" in mode:
            iface.mode = "trunk"
        elif mode == "access":
            iface.mode = "access"
        else:
            iface.mode = "dynamic"  # dynamic auto / desirable / dot1q-tunnel
        return

    match = re.match(r"^switchport access vlan\s+(\d+)", line)
    if match:
        iface.access_vlan = int(match.group(1))
        return

    match = re.match(r"^switchport voice vlan\s+(\d+)", line)
    if match:
        iface.voice_vlan = int(match.group(1))
        return

    match = re.match(r"^switchport trunk native vlan\s+(\d+)", line)
    if match:
        iface.native_vlan = int(match.group(1))
        return

    match = re.match(r"^switchport trunk allowed vlan\s+(.+)$", line)
    if match:
        rest = match.group(1).strip()
        if rest.startswith("add "):
            extra = parse_vlan_list(rest[4:])
            if iface.allowed_vlans is None:
                iface.allowed_vlans = set()
            iface.allowed_vlans |= extra
        elif rest.startswith("except "):
            excluded = parse_vlan_list(rest[7:])
            iface.allowed_vlans = ALL_VLANS - excluded
        else:
            iface.allowed_vlans = parse_vlan_list(rest)
        return

    if line == "no switchport":
        iface.routed = True
    elif line == "shutdown":
        iface.shutdown = True


def parse_config(text):
    """Parse a Cisco IOS running-config into (hostname, vlans, interfaces)."""
    hostname = None
    vlans = {}        # vlan id -> name
    interfaces = {}   # interface name -> Interface
    current_iface = None
    current_vlan = None  # vlan id whose 'name' line we may be inside

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        top_level = not raw_line[:1].isspace()
        if top_level or line == "end":
            current_iface = None
            current_vlan = None
            if line == "end":
                continue
            match = re.match(r"^hostname\s+(\S+)", line)
            if match:
                hostname = match.group(1)
                continue
            match = re.match(r"^vlan\s+([\d,\-\s]+)$", line)
            if match:
                ids = parse_vlan_list(match.group(1).replace(" ", ""))
                for vid in ids:
                    vlans.setdefault(vid, "")
                # Only track a following 'name' line for single-VLAN blocks.
                current_vlan = next(iter(ids)) if len(ids) == 1 else None
                continue
            match = re.match(r"^interface\s+(\S+)", line)
            if match:
                current_iface = Interface(match.group(1))
                interfaces[current_iface.name] = current_iface
                continue
            continue

        # Indented line: inside a vlan or interface block.
        if current_vlan is not None:
            match = re.match(r"^name\s+(.+)$", line)
            if match:
                vlans[current_vlan] = match.group(1).strip()
                continue
        if current_iface is not None:
            _parse_interface_line(current_iface, line)

    return hostname, vlans, interfaces


def audit_device(source, hostname, vlans, interfaces):
    """Run all audit checks for one device. Returns (device_info, findings)."""
    name = hostname or Path(source).stem
    findings = []
    used_vlans = set()

    trunk_count = 0
    access_count = 0

    def add(check, severity, iface_name, message):
        findings.append({
            "check": check,
            "severity": severity,
            "device": name,
            "interface": iface_name,
            "message": message,
        })

    for ifname, iface in interfaces.items():
        # An SVI means its VLAN is in use (L3).
        svi_match = re.match(r"(?i)^vlan(\d+)$", ifname)
        if svi_match:
            used_vlans.add(int(svi_match.group(1)))
            continue
        if iface.routed:
            continue

        if iface.is_trunk:
            trunk_count += 1
        elif iface.has_switchport_cfg:
            access_count += 1

        # Track VLAN usage for the UNUSED_VLAN check.
        if iface.access_vlan:
            used_vlans.add(iface.access_vlan)
        if iface.voice_vlan:
            used_vlans.add(iface.voice_vlan)
        if iface.is_trunk:
            used_vlans.add(iface.native_vlan or 1)
            if iface.allowed_vlans is not None:
                used_vlans.update(iface.allowed_vlans)

        # Check 1: access port in VLAN 1.
        if not iface.is_trunk and iface.has_switchport_cfg:
            effective = iface.access_vlan if iface.access_vlan is not None else 1
            if effective == 1:
                how = ("explicitly assigned to VLAN 1"
                       if iface.access_vlan == 1
                       else "defaults to VLAN 1 (no 'switchport access vlan' configured)")
                add("ACCESS_VLAN_1", "HIGH", ifname,
                    f"Access port {how} — move user ports off the default VLAN 1.")

        # Check 2: trunk with native VLAN 1.
        if iface.is_trunk:
            native = iface.native_vlan or 1
            if native == 1:
                how = ("explicitly set" if iface.native_vlan == 1
                       else "defaults (no 'switchport trunk native vlan' configured)")
                add("NATIVE_VLAN_1", "MEDIUM", ifname,
                    f"Trunk native VLAN is 1 ({how}) — use a dedicated unused VLAN instead.")

        # Check 3: trunk allowing all VLANs.
        if iface.is_trunk:
            if iface.allowed_vlans is None:
                add("TRUNK_ALLOW_ALL", "MEDIUM", ifname,
                    "No 'switchport trunk allowed vlan' list — trunk carries all VLANs 1-4094. "
                    "Prune to only required VLANs.")
            elif ALL_VLANS <= iface.allowed_vlans:
                add("TRUNK_ALLOW_ALL", "MEDIUM", ifname,
                    "Trunk explicitly allows all VLANs 1-4094 — prune to only required VLANs.")

        # Check 5: access VLAN set without explicit 'switchport mode access'.
        if (not iface.is_trunk and not iface.routed
                and iface.access_vlan is not None and iface.mode != "access"):
            add("ACCESS_NO_EXPLICIT_MODE", "MEDIUM", ifname,
                "Has 'switchport access vlan' but no 'switchport mode access' — "
                "port relies on DTP negotiation; set the mode explicitly.")

    # Check 4: VLANs defined but never used.
    for vid in sorted(vlans):
        if vid in IGNORED_VLANS:
            continue
        if vid not in used_vlans:
            vname = vlans[vid] or "(unnamed)"
            add("UNUSED_VLAN", "LOW", f"VLAN {vid}",
                f"VLAN {vid} ({vname}) is defined but not used on any port — "
                f"remove it to keep the VLAN database clean.")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["interface"]))

    device_info = {
        "name": name,
        "source": str(source),
        "interface_count": trunk_count + access_count,
        "trunk_count": trunk_count,
        "access_count": access_count,
        "vlan_count": len(vlans),
    }
    return device_info, findings


def text_report(devices, findings):
    """Render a human-readable audit report."""
    out = []
    out.append("VLAN Audit Report")
    out.append("=" * 60)
    for dev in devices:
        out.append("")
        out.append(f"Device: {dev['name']}  (source: {dev['source']})")
        out.append(f"  Interfaces audited : {dev['interface_count']} "
                   f"(trunk: {dev['trunk_count']}, access: {dev['access_count']})")
        out.append(f"  VLANs defined      : {dev['vlan_count']}")
    out.append("")
    out.append(f"Findings: {len(findings)}")
    out.append("-" * 60)
    if not findings:
        out.append("No issues found. All VLAN best practices are followed.")
    for fnd in findings:
        out.append(f"[{fnd['severity']}] {fnd['check']}")
        out.append(f"    {fnd['device']} / {fnd['interface']}: {fnd['message']}")
    out.append("-" * 60)
    summary = {}
    for fnd in findings:
        summary[fnd["severity"]] = summary.get(fnd["severity"], 0) + 1
    parts = [f"{n} {sev}" for sev in ("HIGH", "MEDIUM", "LOW")
             for n in (summary.get(sev, 0),) if n]
    out.append("Summary: " + (", ".join(parts) if parts else "clean"))
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit Cisco IOS switch configs for VLAN best-practice violations.")
    parser.add_argument("configs", nargs="+",
                        help="Cisco IOS running-config text file(s)")
    parser.add_argument("--json", metavar="FILE", default=None,
                        help="Also write a JSON report to FILE")
    args = parser.parse_args(argv)

    devices = []
    findings = []
    for path in args.configs:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"Error: cannot read {path}: {exc}", file=sys.stderr)
            return 1
        hostname, vlans, interfaces = parse_config(text)
        device_info, dev_findings = audit_device(path, hostname, vlans, interfaces)
        devices.append(device_info)
        findings.extend(dev_findings)

    print(text_report(devices, findings))

    if args.json:
        summary = {}
        for fnd in findings:
            summary[fnd["severity"]] = summary.get(fnd["severity"], 0) + 1
        report = {"devices": devices, "findings": findings, "summary": summary}
        try:
            Path(args.json).write_text(json.dumps(report, indent=2) + "\n",
                                       encoding="utf-8")
        except OSError as exc:
            print(f"Error: cannot write {args.json}: {exc}", file=sys.stderr)
            return 1
        print(f"\nJSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
