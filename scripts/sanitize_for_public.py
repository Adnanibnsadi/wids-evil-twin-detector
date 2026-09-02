#!/usr/bin/env python3
"""
=======================================================
 scripts/sanitize_for_public.py
=======================================================

Prepare a COPY of the WIDS repository for public release.

The sanitizer can:

- Replace private SSID names using a local mapping file
- Replace MAC/BSSID values in text files
- Normalize /home/<username>/ paths to /home/user/
- Remove private capture datasets
- Remove generated AP profiles
- Remove alert logs
- Remove trained model files
- Rebuild a synthetic public profile example
- Produce a local-only sanitization audit file

IMPORTANT
---------
Run this script only on a COPY of the repository or after
committing/backing up your working state.

Real SSID names should NOT be written directly into this
public script.

Instead, optionally create:

    SANITIZE_PRIVATE_INPUT.json

in the repository root.

That file must remain gitignored.

Example local-only structure:

{
    "ssid_map": {
        "My Real Home WiFi": "LAB_AP_01",
        "Another Real SSID": "LAB_AP_02"
    },
    "path_map": {
        "/home/myusername/": "/home/user/"
    }
}
=======================================================
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


# =======================================================
# PATHS
# =======================================================

ROOT = Path(
    __file__
).resolve().parents[1]


PRIVATE_INPUT_FILE = (
    ROOT
    / "SANITIZE_PRIVATE_INPUT.json"
)


AUDIT_FILE = (
    ROOT
    / "SANITIZE_MAP_DO_NOT_COMMIT.json"
)


# =======================================================
# FILE TYPES
# =======================================================

# Files that should not be treated as UTF-8 text.
BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".pkl",
    ".joblib",
    ".pyc",
    ".pcap",
    ".pcapng",
    ".zip",
}


# Directories that should never be scanned.
SKIP_DIRECTORIES = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
}


# =======================================================
# IDENTIFIER TRACKING
# =======================================================

BSSID_MAP = {}


# MAC values used as protocol constants or obvious
# documentation placeholders should not be anonymized.
SAFE_MAC_ADDRESSES = {
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
    "aa:bb:cc:dd:ee:ff",
}


MAC_PATTERN = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}"
    r"[0-9A-Fa-f]{2}\b"
)


HOME_PATH_PATTERN = re.compile(
    r"/home/[^/\s\"']+/"
)


# =======================================================
# PRIVATE LOCAL MAP
# =======================================================

def load_private_mapping():
    """
    Load optional private sanitization values.

    The mapping file must remain local and gitignored.

    Returns
    -------
    tuple
        ssid_map, path_map
    """

    if not PRIVATE_INPUT_FILE.exists():

        print(
            "[*] No private SSID mapping file found."
        )

        print(
            "[*] Generic MAC and home-path "
            "sanitization will still run."
        )

        print(
            "[*] If real SSID names exist in source "
            "or documentation, create:"
        )

        print(
            f"    {PRIVATE_INPUT_FILE.name}"
        )

        return (
            {},
            {},
        )


    try:

        data = json.loads(
            PRIVATE_INPUT_FILE.read_text(
                encoding="utf-8"
            )
        )

    except Exception as error:

        raise RuntimeError(
            "Could not read private sanitization "
            f"mapping: {error}"
        ) from error


    ssid_map = data.get(
        "ssid_map",
        {},
    )


    path_map = data.get(
        "path_map",
        {},
    )


    if not isinstance(
        ssid_map,
        dict,
    ):

        raise ValueError(
            "'ssid_map' must be a JSON object."
        )


    if not isinstance(
        path_map,
        dict,
    ):

        raise ValueError(
            "'path_map' must be a JSON object."
        )


    return (
        {
            str(old):
                str(new)
            for old, new
            in ssid_map.items()
            if str(old)
        },
        {
            str(old):
                str(new)
            for old, new
            in path_map.items()
            if str(old)
        },
    )


# =======================================================
# BSSID ANONYMIZATION
# =======================================================

def normalize_mac(
    value,
):
    """
    Normalize dash- or colon-separated MAC addresses.
    """

    return (
        str(
            value
        )
        .strip()
        .lower()
        .replace(
            "-",
            ":",
        )
    )


def fake_bssid(
    real,
):
    """
    Convert a MAC/BSSID into a deterministic synthetic
    locally administered unicast MAC.

    Deterministic replacement is useful because the same
    real BSSID will map to the same synthetic value during
    one sanitization run.
    """

    real = normalize_mac(
        real
    )


    if real in SAFE_MAC_ADDRESSES:

        return real


    if real in BSSID_MAP:

        return BSSID_MAP[
            real
        ]


    digest = hashlib.sha256(
        real.encode(
            "utf-8"
        )
    ).hexdigest()


    # 02 sets the locally administered bit while
    # remaining a unicast address.
    parts = [
        "02",
        digest[0:2],
        digest[2:4],
        digest[4:6],
        digest[6:8],
        digest[8:10],
    ]


    synthetic_mac = ":".join(
        parts
    )


    BSSID_MAP[
        real
    ] = synthetic_mac


    return synthetic_mac


# =======================================================
# TEXT SANITIZATION
# =======================================================

def scrub_text(
    text,
    ssid_map,
    path_map,
):
    """
    Sanitize identifiers inside a text document.
    """

    sanitized = text


    # Replace longer strings first in case one SSID or
    # path is contained inside another.
    for old, new in sorted(
        ssid_map.items(),
        key=lambda item:
            len(
                item[0]
            ),
        reverse=True,
    ):

        sanitized = sanitized.replace(
            old,
            new,
        )


    for old, new in sorted(
        path_map.items(),
        key=lambda item:
            len(
                item[0]
            ),
        reverse=True,
    ):

        sanitized = sanitized.replace(
            old,
            new,
        )


    # Generic Linux home-directory sanitization.
    sanitized = HOME_PATH_PATTERN.sub(
        "/home/user/",
        sanitized,
    )


    # Replace MAC/BSSID-looking values while preserving
    # protocol constants and obvious placeholders.
    def replace_mac(
        match,
    ):

        original = match.group(
            0
        )


        normalized = normalize_mac(
            original
        )


        if normalized in SAFE_MAC_ADDRESSES:

            return original


        return fake_bssid(
            normalized
        )


    sanitized = MAC_PATTERN.sub(
        replace_mac,
        sanitized,
    )


    return sanitized


# =======================================================
# FILE SANITIZATION
# =======================================================

def should_skip_file(
    path,
):
    """
    Determine whether a file should not be text-scrubbed.
    """

    if not path.is_file():

        return True


    if path in {
        PRIVATE_INPUT_FILE,
        AUDIT_FILE,
    }:

        return True


    if path.suffix.lower() in BINARY_SUFFIXES:

        return True


    return False


def scrub_file(
    path,
    ssid_map,
    path_map,
):
    """
    Sanitize one textual repository file.
    """

    if should_skip_file(
        path
    ):

        return


    try:

        original = path.read_text(
            encoding="utf-8",
            errors="strict",
        )

    except (
        UnicodeDecodeError,
        OSError,
    ):

        return


    sanitized = scrub_text(
        original,
        ssid_map,
        path_map,
    )


    if sanitized == original:

        return


    path.write_text(
        sanitized,
        encoding="utf-8",
    )


    print(
        "scrubbed: "
        f"{path.relative_to(ROOT)}"
    )


# =======================================================
# REMOVE PRIVATE ARTIFACTS
# =======================================================

def remove_private_artifacts():
    """
    Delete locally generated artifacts that should not be
    included in a public repository.
    """

    private_files = [
        ROOT
        / "data"
        / "bssid_profiles.json",

        ROOT
        / "data"
        / "ap_profiles.json",

        ROOT
        / "logs"
        / "alerts.log",
    ]


    for path in private_files:

        if path.exists():

            path.unlink()

            print(
                "removed private: "
                f"{path.relative_to(ROOT)}"
            )


    # Remove root-level data CSV captures while
    # preserving synthetic files under data/samples/.
    data_dir = (
        ROOT
        / "data"
    )


    if data_dir.exists():

        for path in data_dir.glob(
            "*.csv"
        ):

            path.unlink()

            print(
                "removed private dataset: "
                f"{path.relative_to(ROOT)}"
            )


    # Remove serialized trained models.
    models_dir = (
        ROOT
        / "models"
    )


    if models_dir.exists():

        for pattern in (
            "*.pkl",
            "*.joblib",
        ):

            for path in models_dir.glob(
                pattern
            ):

                path.unlink()

                print(
                    "removed model: "
                    f"{path.relative_to(ROOT)}"
                )


# =======================================================
# SYNTHETIC PUBLIC EXAMPLE
# =======================================================

def write_sample_profile():
    """
    Create a small synthetic AP-profile example suitable
    for public documentation and tests.
    """

    sample = {
        "02:10:00:00:00:01": {
            "ssid":
                "LAB_AP_01",

            "bssid":
                "02:10:00:00:00:01",

            "ie_count":
                20,

            "rate_count":
                12,

            "security":
                "WPA2/WPA3",

            "channel":
                6,

            "beacon_interval":
                100,

            "clock_skew_mean":
                -0.00001289,

            "clock_skew_std":
                0.00004620,

            "rssi_mean":
                -56.0,

            "rssi_min":
                -84.0,

            "rssi_max":
                -48.0,

            "seq_jump_mean":
                1.3,

            "seq_jump_std":
                2.0,

            "total_beacons":
                1000,

            "profile_built":
                "2026-01-01 00:00:00",

            "notes":
                (
                    "Synthetic example for "
                    "documentation/testing only."
                ),
        },

        "02:10:00:00:00:02": {
            "ssid":
                "LAB_AP_02",

            "bssid":
                "02:10:00:00:00:02",

            "ie_count":
                15,

            "rate_count":
                12,

            "security":
                "WPA2/WPA3",

            "channel":
                11,

            "beacon_interval":
                100,

            "clock_skew_mean":
                -0.00001036,

            "clock_skew_std":
                0.00005789,

            "rssi_mean":
                -75.0,

            "rssi_min":
                -90.0,

            "rssi_max":
                -68.0,

            "seq_jump_mean":
                1.4,

            "seq_jump_std":
                2.1,

            "total_beacons":
                1000,

            "profile_built":
                "2026-01-01 00:00:00",

            "notes":
                (
                    "Synthetic example for "
                    "documentation/testing only."
                ),
        },
    }


    output = (
        ROOT
        / "data"
        / "samples"
        / "bssid_profiles.example.json"
    )


    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    output.write_text(
        json.dumps(
            sample,
            indent=2,
        ),
        encoding="utf-8",
    )


    print(
        "wrote synthetic sample: "
        f"{output.relative_to(ROOT)}"
    )


# =======================================================
# LOCAL AUDIT
# =======================================================

def write_audit(
    ssid_map,
    path_map,
):
    """
    Save a LOCAL-ONLY record of replacements.

    This file may contain sensitive identifiers and must
    never be committed.
    """

    audit_data = {
        "ssid_map":
            ssid_map,

        "path_map":
            path_map,

        "bssid_map":
            BSSID_MAP,
    }


    AUDIT_FILE.write_text(
        json.dumps(
            audit_data,
            indent=2,
        ),
        encoding="utf-8",
    )


    print(
        "local audit map: "
        f"{AUDIT_FILE.name}"
    )


# =======================================================
# MAIN
# =======================================================

def main():

    print(
        "\n"
        + "=" * 68
    )

    print(
        "  PUBLIC-REPOSITORY SANITIZER"
    )

    print(
        "=" * 68
    )

    print(
        f"  Repository : {ROOT}"
    )

    print(
        "  WARNING    : Run on a copy or committed "
        "working tree."
    )

    print(
        "=" * 68
        + "\n"
    )


    (
        ssid_map,
        path_map,
    ) = load_private_mapping()


    for path in ROOT.rglob(
        "*"
    ):

        relative_parts = set(
            path.relative_to(
                ROOT
            ).parts
        )


        if (
            relative_parts
            & SKIP_DIRECTORIES
        ):

            continue


        scrub_file(
            path,
            ssid_map,
            path_map,
        )


    remove_private_artifacts()


    # Recreate the public sample after sanitization so
    # repeated runs end with the same known-safe example.
    write_sample_profile()


    write_audit(
        ssid_map,
        path_map,
    )


    print(
        "\n"
        + "=" * 68
    )

    print(
        "  SANITIZATION COMPLETE"
    )

    print(
        "=" * 68
    )

    print(
        "Before pushing:"
    )

    print(
        "  1. Review git diff carefully."
    )

    print(
        "  2. Search for private SSIDs and BSSIDs."
    )

    print(
        "  3. Confirm datasets/logs/models are absent."
    )

    print(
        "  4. Confirm SANITIZE_PRIVATE_INPUT.json "
        "is not staged."
    )

    print(
        "  5. Confirm SANITIZE_MAP_DO_NOT_COMMIT.json "
        "is not staged."
    )

    print(
        "=" * 68
        + "\n"
    )


if __name__ == "__main__":

    main()
