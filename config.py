#!/usr/bin/env python3
"""
=======================================================
 config.py - Project Configuration
=======================================================

Central configuration for the Hybrid Wireless Intrusion
Detection System.

Responsibilities:

- Resolve repository-relative paths
- Identify the invoking user for display purposes
- Detect monitor-mode wireless interfaces
- Assist with monitor-mode setup
- Define channel-hopping and profiling parameters
- Define paths used by both the current WIDS workflow
  and retained legacy experiments

No user-specific absolute project path is required.
=======================================================
"""

import os
import shutil
import subprocess
import time


# =======================================================
# PROJECT / USER PATHS
# =======================================================

def get_project_root():
    """
    Return the directory containing config.py.

    This allows the repository to be moved between users
    and installation locations without hardcoded paths.
    """

    return os.path.dirname(
        os.path.abspath(__file__)
    )


def get_real_user():
    """
    Return the username that launched the process.

    When running through sudo, SUDO_USER normally contains
    the original account name.

    This value is used for display only. Project paths are
    always based on get_project_root().
    """

    return (
        os.environ.get("SUDO_USER")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or "unknown"
    )


# =======================================================
# COMMAND AVAILABILITY
# =======================================================

def command_available(command):
    """
    Return True when a command exists in PATH.
    """

    return shutil.which(command) is not None


# =======================================================
# MONITOR-MODE INTERFACE DETECTION
# =======================================================

def find_monitor_interface():
    """
    Return the first wireless interface detected in
    monitor mode.

    Returns
    -------
    str or None
        Interface name such as 'wlan0mon', or None when no
        monitor-mode interface is found.
    """

    if not command_available(
        "iwconfig"
    ):

        return None


    try:

        result = subprocess.run(
            [
                "iwconfig",
            ],
            capture_output=True,
            text=True,
            check=False,
        )


        current_interface = None


        for line in result.stdout.splitlines():

            # Interface sections begin at column zero.
            if (
                line
                and not line[0].isspace()
            ):

                current_interface = (
                    line.split()[0]
                )


            if (
                "Mode:Monitor"
                in line
                and current_interface
            ):

                return current_interface


    except (
        OSError,
        subprocess.SubprocessError,
    ):

        pass


    return None


def find_wireless_interfaces():
    """
    Return wireless interfaces visible through iwconfig.

    Interfaces explicitly reported as having no wireless
    extensions are excluded.
    """

    if not command_available(
        "iwconfig"
    ):

        return []


    interfaces = []


    try:

        result = subprocess.run(
            [
                "iwconfig",
            ],
            capture_output=True,
            text=True,
            check=False,
        )


        for line in result.stdout.splitlines():

            if (
                not line
                or line[0].isspace()
            ):

                continue


            first_token = (
                line.split()[0]
            )


            if (
                "no wireless extensions"
                in line.lower()
            ):

                continue


            if first_token not in interfaces:

                interfaces.append(
                    first_token
                )


    except (
        OSError,
        subprocess.SubprocessError,
    ):

        pass


    return interfaces


# =======================================================
# MONITOR-MODE SETUP
# =======================================================

def enable_monitor_mode(
    interface=None,
):
    """
    Attempt to enable monitor mode with airmon-ng.

    Parameters
    ----------
    interface : str or None
        Wireless interface to use. When omitted, the first
        detected wireless interface is selected.

    Returns
    -------
    str or None
        Monitor-mode interface name when successful.
    """

    existing = (
        find_monitor_interface()
    )


    if existing:

        print(
            f"[✓] Monitor mode already active: "
            f"{existing}"
        )

        return existing


    if not command_available(
        "airmon-ng"
    ):

        print(
            "[ERROR] airmon-ng was not found."
        )

        print(
            "[ERROR] Install the Aircrack-ng tools "
            "or enable monitor mode manually."
        )

        return None


    if not interface:

        interfaces = (
            find_wireless_interfaces()
        )


        if not interfaces:

            print(
                "[ERROR] No wireless interfaces found."
            )

            return None


        interface = interfaces[
            0
        ]


        print(
            f"[*] Using wireless interface: "
            f"{interface}"
        )


    print(
        f"[*] Attempting to enable monitor mode "
        f"on {interface}..."
    )


    # airmon-ng may stop processes that interfere with
    # monitor mode. Users should be aware that this can
    # temporarily interrupt normal network management.
    subprocess.run(
        [
            "airmon-ng",
            "check",
            "kill",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


    subprocess.run(
        [
            "airmon-ng",
            "start",
            interface,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


    time.sleep(
        2
    )


    monitor_interface = (
        find_monitor_interface()
    )


    if monitor_interface:

        print(
            f"[✓] Monitor mode enabled: "
            f"{monitor_interface}"
        )

        return monitor_interface


    print(
        "[ERROR] Monitor-mode interface "
        "could not be detected."
    )

    return None


# =======================================================
# PROJECT PATHS
# =======================================================

PROJECT_ROOT = (
    get_project_root()
)

DATA_DIR = os.path.join(
    PROJECT_ROOT,
    "data",
)

MODELS_DIR = os.path.join(
    PROJECT_ROOT,
    "models",
)

LOGS_DIR = os.path.join(
    PROJECT_ROOT,
    "logs",
)

REPORTS_DIR = os.path.join(
    PROJECT_ROOT,
    "reports",
)

MODULES_DIR = os.path.join(
    PROJECT_ROOT,
    "modules",
)


# =======================================================
# CURRENT MULTI-AP WORKFLOW
# =======================================================

ALL_APS_DATA_FILE = os.path.join(
    DATA_DIR,
    "all_aps_normal.csv",
)

BSSID_PROFILES_FILE = os.path.join(
    DATA_DIR,
    "bssid_profiles.json",
)

PER_BSSID_MODELS_FILE = os.path.join(
    MODELS_DIR,
    "per_bssid_models.pkl",
)

GLOBAL_MODEL_FILE = os.path.join(
    MODELS_DIR,
    "global_model.pkl",
)


# =======================================================
# LEGACY / EXPERIMENTAL WORKFLOW PATHS
# =======================================================

# Retained for the older single-AP profiler and supervised
# Random Forest baseline. These are not required by the
# current primary live detector.

NORMAL_DATA_FILE = os.path.join(
    DATA_DIR,
    "normal_data.csv",
)

EVIL_TWIN_DATA_FILE = os.path.join(
    DATA_DIR,
    "evil_twin_data.csv",
)

COMBINED_DATA_FILE = os.path.join(
    DATA_DIR,
    "combined_data.csv",
)

AP_PROFILES_FILE = os.path.join(
    DATA_DIR,
    "ap_profiles.json",
)

MODEL_FILE = os.path.join(
    MODELS_DIR,
    "detector_model.pkl",
)

SCALER_FILE = os.path.join(
    MODELS_DIR,
    "scaler.pkl",
)

ENCODER_FILE = os.path.join(
    MODELS_DIR,
    "encoder.pkl",
)


# =======================================================
# LOG FILES
# =======================================================

ALERT_LOG_FILE = os.path.join(
    LOGS_DIR,
    "alerts.log",
)

DETECTION_LOG_FILE = os.path.join(
    LOGS_DIR,
    "detections.log",
)


# =======================================================
# USER INFORMATION
# =======================================================

REAL_USER = (
    get_real_user()
)


# =======================================================
# WIRELESS CHANNELS
# =======================================================

CHANNELS_2GHZ = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
]


CHANNELS_5GHZ = [
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    149,
    153,
    157,
    161,
]


ALL_CHANNELS = (
    CHANNELS_2GHZ
    + CHANNELS_5GHZ
)


# =======================================================
# CAPTURE / PROFILING PARAMETERS
# =======================================================

# Time spent on each channel during hopping.
HOP_INTERVAL = 0.5


# Used by the retained legacy single-AP profiler.
PROFILE_DURATION = 60


# Retained for compatibility with older experimental code.
# The current simulator controls its own transmission delay.
BEACON_DELAY = 0.1


# Minimum number of observations used by the older
# single-AP profiling progress display.
MIN_SAMPLES_NEEDED = 50


# =======================================================
# MODEL / REPRODUCIBILITY SETTINGS
# =======================================================

# Shared deterministic seed for scikit-learn experiments.
RANDOM_STATE = 42


# Legacy heuristic threshold retained for compatibility.
# The current live detector uses its own evidence and
# Isolation Forest decision thresholds.
ANOMALY_THRESHOLD = 0.6


# =======================================================
# DIRECTORY SETUP
# =======================================================

def setup_directories():
    """
    Create runtime directories when they do not exist.
    """

    directories = [
        DATA_DIR,
        MODELS_DIR,
        LOGS_DIR,
        REPORTS_DIR,
        MODULES_DIR,
    ]


    for directory in directories:

        os.makedirs(
            directory,
            exist_ok=True,
        )


    print(
        "[✓] Project directories ready"
    )


# =======================================================
# CONFIGURATION SUMMARY
# =======================================================

def print_config():
    """
    Print a concise runtime configuration summary.
    """

    monitor_interface = (
        find_monitor_interface()
    )


    print(
        "\n"
        + "=" * 60
    )

    print(
        "  SYSTEM CONFIGURATION"
    )

    print(
        "=" * 60
    )

    print(
        f"  User              : "
        f"{REAL_USER}"
    )

    print(
        f"  Project root      : "
        f"{PROJECT_ROOT}"
    )

    print(
        f"  Data directory    : "
        f"{DATA_DIR}"
    )

    print(
        f"  Models directory  : "
        f"{MODELS_DIR}"
    )

    print(
        f"  Monitor interface : "
        f"{monitor_interface or 'Not detected'}"
    )

    print(
        "=" * 60
        + "\n"
    )
