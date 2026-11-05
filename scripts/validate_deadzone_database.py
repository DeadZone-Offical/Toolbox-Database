#!/usr/bin/env python3
"""DeadZone read-only configuration contract audit; never prints keybox data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from datetime import date
import xml.etree.ElementTree as ET

IDENTITY = ("BRAND", "DEVICE", "MANUFACTURER", "MODEL", "FINGERPRINT", "PRODUCT")
PACKAGE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$")
TARGET = re.compile(r"^([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)([!?#]*)$")


def load_json(root: Path, name: str):
    path = root / name
    if path.stat().st_size > 5_000_000:
        raise ValueError(f"DeadZone {name}: unexpected size")
    return json.loads(path.read_text(encoding="utf-8"))


def audit(root: Path) -> dict[str, int]:
    pif = load_json(root, "pif-props.json")
    if not isinstance(pif, dict) or any(not isinstance(pif.get(k), str) or not pif[k] for k in IDENTITY):
        raise ValueError("DeadZone: PIF identity document is incomplete")
    patch = pif.get("SECURITY_PATCH")
    if patch:
        try:
            date.fromisoformat(patch)
        except (ValueError, TypeError) as exc:
            raise ValueError("DeadZone: invalid PIF patch date") from exc
    games = load_json(root, "app-props.json")
    if not isinstance(games, dict):
        raise ValueError("DeadZone: app profile mapping is invalid")
    for pkg, props in games.items():
        if not PACKAGE.fullmatch(pkg) or not isinstance(props, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in props.items()
        ):
            raise ValueError("DeadZone: invalid app profile entry")
    devices = load_json(root, "device-props.json")
    if not isinstance(devices, dict) or not isinstance(devices.get("devices"), list):
        raise ValueError("DeadZone: device catalog is invalid")
    for device in devices["devices"]:
        if not isinstance(device, dict) or any(not isinstance(device.get(k), str) or not device[k] for k in IDENTITY):
            raise ValueError("DeadZone: incomplete device catalog entry")
    hidden = load_json(root, "blacklist.json")
    if not isinstance(hidden, list) or not all(isinstance(p, str) and PACKAGE.fullmatch(p) for p in hidden):
        raise ValueError("DeadZone: blacklist must be an array of package IDs")
    targets = (root / "target-list.txt").read_text(encoding="utf-8").splitlines()
    count = 0
    for raw in targets:
        value = raw.strip()
        if not value:
            continue
        m = TARGET.fullmatch(value)
        if m is None or len(set(m.group(2))) != len(m.group(2)):
            raise ValueError("DeadZone: target list contains invalid mode syntax")
        count += 1
    keybox_path = root / "keybox.xml"
    if keybox_path.stat().st_size > 256_000:
        raise ValueError("DeadZone: keybox document exceeds safe size")
    # DeadZone only checks XML shape, without logging, sharing or exporting private keys.
    key_root = ET.parse(keybox_path).getroot()
    if key_root.tag != "AndroidAttestation":
        raise ValueError("DeadZone: unexpected keybox XML root")
    return {"app_profiles": len(games), "device_profiles": len(devices["devices"]),
            "hidden_packages": len(hidden), "target_packages": count,
            "keybox_xml_shape_checked": 1}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = cli.parse_args()
    print("DeadZone database schema checks passed:", audit(args.root))