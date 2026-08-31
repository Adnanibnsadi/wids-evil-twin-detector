#!/usr/bin/env python3
"""Anonymize lab identifiers for public release. Run on a COPY of the repo."""
import json, re, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Known real tokens from this lab (extend if needed)
SSID_MAP = {
    "LAB_AP_01": "LAB_AP_01",
    "LAB_AP_02": "LAB_AP_02",
    "LAB_AP_03": "LAB_AP_03",
    "LAB_AP_04": "LAB_AP_04",
    "LAB_AP_05": "LAB_AP_05",
    "LAB_AP_06": "LAB_AP_06",
    "LAB_AP_07": "LAB_AP_07",
    "LAB_AP_08": "LAB_AP_08",
    "LAB_AP_08": "LAB_AP_08",
    "LAB_AP_09": "LAB_AP_09",
    "LAB_AP_10": "LAB_AP_10",
    "LAB_AP_11": "LAB_AP_11",
    "LAB_AP_12": "LAB_AP_12",
    "LAB_AP_13": "LAB_AP_13",
    "LAB_AP_14": "LAB_AP_14",
    "LAB_AP_15": "LAB_AP_15",
    "LAB_AP_16": "LAB_AP_16",
}

BSSID_MAP = {}  # filled deterministically

def fake_bssid(real: str) -> str:
    real = real.strip().lower()
    if real in BSSID_MAP:
        return BSSID_MAP[real]
    h = hashlib.sha256(real.encode()).hexdigest()
    # Locally administered unicast-looking lab MACs
    parts = ["02"] + [h[i:i+2] for i in range(0, 10, 2)]
    mac = ":".join(parts)
    BSSID_MAP[real] = mac
    return mac

def scrub_text(s: str) -> str:
    for old, new in SSID_MAP.items():
        s = s.replace(old, new)
    # MAC addresses
    def repl_mac(m):
        return fake_bssid(m.group(0))
    s = re.sub(
        r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b",
        repl_mac,
        s,
    )
    s = s.replace("/home/user/", "/home/user/")
    s = s.replace("/home/user/", "/home/user/")
    s = re.sub(r"/home/user/]+/", "/home/user/", s)
    return s

def scrub_file(path: Path):
    if not path.is_file():
        return
    if path.suffix.lower() in {".png", ".pkl", ".pyc", ".csv"}:
        return
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return
    new = scrub_text(text)
    if new != text:
        path.write_text(new, encoding="utf-8")
        print(f"scrubbed: {path.relative_to(ROOT)}")

def write_sample_profile():
    sample = {
        "02:26:a4:ee:f9:ed": {
            "ssid": "LAB_AP_01",
            "bssid": "02:26:a4:ee:f9:ed",
            "ie_count": 20,
            "rate_count": 12,
            "security": "WPA2/WPA3",
            "channel": 8,
            "beacon_interval": 100,
            "clock_skew_mean": -0.00001289,
            "clock_skew_std": 0.00004620,
            "rssi_mean": -56.0,
            "rssi_min": -84.0,
            "rssi_max": -48.0,
            "seq_jump_mean": 1.3,
            "seq_jump_std": 2.0,
            "total_beacons": 1000,
            "profile_built": "2026-01-01 00:00:00",
            "notes": "Synthetic example for CI/docs — not a real network",
        },
        "02:90:d8:0f:a8:65": {
            "ssid": "LAB_AP_02",
            "bssid": "02:90:d8:0f:a8:65",
            "ie_count": 15,
            "rate_count": 12,
            "security": "WPA2/WPA3",
            "channel": 10,
            "beacon_interval": 100,
            "clock_skew_mean": -0.00001036,
            "clock_skew_std": 0.00005789,
            "rssi_mean": -75.0,
            "rssi_min": -90.0,
            "rssi_max": -68.0,
            "seq_jump_mean": 1.4,
            "seq_jump_std": 2.1,
            "total_beacons": 1000,
            "profile_built": "2026-01-01 00:00:00",
            "notes": "Synthetic example for CI/docs",
        },
    }
    out = ROOT / "data" / "samples" / "bssid_profiles.example.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sample, indent=2), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")

def main():
    skip = {"venv", ".git", "__pycache__"}
    for path in ROOT.rglob("*"):
        if any(p in skip for p in path.parts):
            continue
        scrub_file(path)
    # Remove private artifacts if present
    for rel in [
        "data/all_aps_normal.csv",
        "data/normal_data.csv",
        "data/evil_twin_data.csv",
        "data/bssid_profiles.json",
        "data/ap_profiles.json",
        "logs/alerts.log",
    ]:
        p = ROOT / rel
        if p.exists():
            p.unlink()
            print(f"removed private: {rel}")
    for p in (ROOT / "models").glob("*.pkl"):
        p.unlink()
        print(f"removed model: {p.name}")
    write_sample_profile()
    # Mapping audit (local only — do not commit)
    audit = ROOT / "SANITIZE_MAP_DO_NOT_COMMIT.json"
    audit.write_text(
        json.dumps({"ssid_map": SSID_MAP, "bssid_map": BSSID_MAP}, indent=2),
        encoding="utf-8",
    )
    print(f"audit map (gitignored if named well): {audit}")
    print("Done. Delete SANITIZE_MAP_DO_NOT_COMMIT.json before push.")

if __name__ == "__main__":
    main()
