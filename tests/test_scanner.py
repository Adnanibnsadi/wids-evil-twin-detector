"""
Unit tests for modules/scanner.py.

These tests use synthetic Scapy beacon frames and do not
require root privileges, monitor mode, packet capture, or
wireless hardware.
"""

import pytest

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
)


from modules import scanner


TEST_SSID = "LAB_AP_01"
TEST_BSSID = "02:10:00:00:00:01"
TEST_CHANNEL = 6


@pytest.fixture(autouse=True)
def reset_scanner_state():
    """
    Ensure every test begins and ends with an empty
    discovered-network dictionary.
    """

    scanner.discovered_networks.clear()

    yield

    scanner.discovered_networks.clear()


def build_beacon(
    ssid=TEST_SSID,
    bssid=TEST_BSSID,
    channel=TEST_CHANNEL,
    security="open",
):
    """
    Build a small synthetic 802.11 beacon frame suitable
    for testing scanner parsing logic.
    """

    capabilities = "ESS"

    if security == "wep":
        capabilities = "ESS+privacy"

    packet = (
        Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Beacon(
            cap=capabilities,
        )
        / Dot11Elt(
            ID="SSID",
            info=ssid.encode(),
        )
        / Dot11Elt(
            ID="Rates",
            info=b"\x82\x84\x8b\x96",
        )
        / Dot11Elt(
            ID="DSset",
            info=bytes(
                [
                    channel,
                ]
            ),
        )
    )

    if security == "wpa":

        packet = (
            packet
            / Dot11Elt(
                ID=221,
                info=(
                    b"\x00\x50\xf2\x01"
                    b"\x01\x00"
                ),
            )
        )

    elif security == "wpa2":

        packet = (
            packet
            / Dot11Elt(
                ID=48,
                info=b"\x01\x00",
            )
        )

    return packet


def test_extract_ssid():
    """
    Scanner should return the advertised SSID.
    """

    packet = build_beacon()

    assert (
        scanner.extract_ssid(
            packet
        )
        == TEST_SSID
    )


def test_extract_hidden_ssid():
    """
    An empty SSID Information Element should be presented
    as <Hidden>.
    """

    packet = build_beacon(
        ssid="",
    )

    assert (
        scanner.extract_ssid(
            packet
        )
        == "<Hidden>"
    )


def test_extract_channel():
    """
    Scanner should read the DS Parameter Set channel.
    """

    packet = build_beacon(
        channel=11,
    )

    assert (
        scanner.extract_channel(
            packet
        )
        == 11
    )


def test_open_security_detection():
    """
    Beacon without privacy, WPA, or RSN information should
    be classified as Open.
    """

    packet = build_beacon(
        security="open",
    )

    assert (
        scanner.extract_security(
            packet
        )
        == "Open"
    )


def test_wep_security_detection():
    """
    Privacy capability without WPA/RSN information is
    classified by the lightweight scanner as WEP.
    """

    packet = build_beacon(
        security="wep",
    )

    assert (
        scanner.extract_security(
            packet
        )
        == "WEP"
    )


def test_wpa_security_detection():
    """
    Microsoft WPA vendor Information Element should be
    classified as WPA.
    """

    packet = build_beacon(
        security="wpa",
    )

    assert (
        scanner.extract_security(
            packet
        )
        == "WPA"
    )


def test_rsn_security_detection():
    """
    Presence of an RSN Information Element should be
    classified using the scanner's current WPA2/WPA3
    grouped category.
    """

    packet = build_beacon(
        security="wpa2",
    )

    assert (
        scanner.extract_security(
            packet
        )
        == "WPA2/WPA3"
    )


def test_scan_handler_adds_network():
    """
    A beacon from a previously unseen BSSID should create
    one network entry.
    """

    packet = build_beacon()

    scanner.scan_handler(
        packet
    )

    assert (
        TEST_BSSID
        in scanner.discovered_networks
    )

    network = (
        scanner.discovered_networks[
            TEST_BSSID
        ]
    )

    assert (
        network["ssid"]
        == TEST_SSID
    )

    assert (
        network["channel"]
        == TEST_CHANNEL
    )

    assert (
        network["beacons"]
        == 1
    )


def test_scan_handler_counts_repeated_beacons():
    """
    Multiple beacons from the same BSSID should increment
    the observation counter rather than create duplicates.
    """

    packet = build_beacon()

    scanner.scan_handler(
        packet
    )

    scanner.scan_handler(
        packet
    )

    assert (
        len(
            scanner.discovered_networks
        )
        == 1
    )

    assert (
        scanner.discovered_networks[
            TEST_BSSID
        ]["beacons"]
        == 2
    )


def test_hidden_ssid_can_be_updated():
    """
    If the first observation is hidden and a later frame
    exposes the SSID, the stored network name should be
    updated.
    """

    hidden_packet = build_beacon(
        ssid="",
    )

    visible_packet = build_beacon(
        ssid=TEST_SSID,
    )

    scanner.scan_handler(
        hidden_packet
    )

    assert (
        scanner.discovered_networks[
            TEST_BSSID
        ]["ssid"]
        == "<Hidden>"
    )

    scanner.scan_handler(
        visible_packet
    )

    assert (
        scanner.discovered_networks[
            TEST_BSSID
        ]["ssid"]
        == TEST_SSID
    )


def test_sorted_networks_orders_by_rssi():
    """
    Network records should be sorted from strongest to
    weakest observed RSSI.
    """

    networks = {
        "02:00:00:00:00:01": {
            "ssid": "AP_1",
            "rssi": -80,
        },

        "02:00:00:00:00:02": {
            "ssid": "AP_2",
            "rssi": -40,
        },

        "02:00:00:00:00:03": {
            "ssid": "AP_3",
            "rssi": -60,
        },
    }

    ordered = scanner.sorted_networks(
        networks
    )

    assert [
        network["rssi"]
        for network in ordered
    ] == [
        -40,
        -60,
        -80,
    ]


def test_non_beacon_packet_is_ignored():
    """
    Non-beacon 802.11 packets should not create network
    records.
    """

   packet = Dot11(
    type=2,
    addr1="ff:ff:ff:ff:ff:ff",
    addr2=TEST_BSSID,
    addr3=TEST_BSSID,
)

    scanner.scan_handler(
        packet
    )

    assert (
        scanner.discovered_networks
        == {}
    )
