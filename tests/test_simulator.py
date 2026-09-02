"""
Unit tests for modules/simulator.py.

These tests construct synthetic beacon frames in memory.
They do not transmit packets and do not require root,
monitor mode, or wireless hardware.
"""

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
)

from modules.simulator import build_attack_frame


TEST_SSID = "LAB_AP_01"
TEST_BSSID = "02:10:00:00:00:01"
TEST_CHANNEL = 6


def get_ie_ids(packet):
    """
    Return Information Element IDs in packet order.
    """

    ids = []

    element = packet.getlayer(
        Dot11Elt
    )

    while isinstance(
        element,
        Dot11Elt,
    ):
        ids.append(
            element.ID
        )

        element = element.payload

    return ids


def find_ie(
    packet,
    target_id,
):
    """
    Return the first Information Element with target ID.
    """

    element = packet.getlayer(
        Dot11Elt
    )

    while isinstance(
        element,
        Dot11Elt,
    ):

        if element.ID == target_id:
            return element

        element = element.payload

    return None


def test_beacon_uses_broadcast_destination():
    """
    802.11 beacon management frames should use the
    broadcast destination address.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=True,
    )

    assert (
        packet[Dot11].addr1.lower()
        == "ff:ff:ff:ff:ff:ff"
    )


def test_beacon_uses_requested_bssid():
    """
    Source and BSSID fields should match the BSSID passed
    to the frame builder.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=True,
    )

    assert (
        packet[Dot11].addr2.lower()
        == TEST_BSSID
    )

    assert (
        packet[Dot11].addr3.lower()
        == TEST_BSSID
    )


def test_sequence_number_is_encoded_correctly():
    """
    The sequence number is stored in the upper 12 bits of
    the Sequence Control field.
    """

    sequence_number = 1234

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=sequence_number,
        bssid_clone=True,
    )

    observed_sequence = (
        packet[Dot11].SC >> 4
    )

    assert observed_sequence == sequence_number


def test_ssid_information_element():
    """
    The generated SSID IE should contain the requested
    network name.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=True,
    )

    ssid_ie = find_ie(
        packet,
        0,
    )

    assert ssid_ie is not None
    assert ssid_ie.info == TEST_SSID.encode()


def test_channel_information_element():
    """
    The DS Parameter Set IE should advertise the requested
    channel.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=True,
    )

    channel_ie = find_ie(
        packet,
        3,
    )

    assert channel_ie is not None
    assert channel_ie.info == bytes(
        [
            TEST_CHANNEL,
        ]
    )


def test_bssid_clone_mode_has_extended_rates():
    """
    The current BSSID-spoofing simulation intentionally
    creates a slightly richer synthetic beacon structure.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=True,
    )

    ie_ids = get_ie_ids(
        packet
    )

    assert 0 in ie_ids
    assert 1 in ie_ids
    assert 3 in ie_ids
    assert 50 in ie_ids


def test_standard_rogue_mode_uses_simpler_ie_structure():
    """
    Standard rogue mode should not include the additional
    Extended Supported Rates IE used by BSSID-clone mode.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=False,
    )

    ie_ids = get_ie_ids(
        packet
    )

    assert 0 in ie_ids
    assert 1 in ie_ids
    assert 3 in ie_ids
    assert 50 not in ie_ids


def test_generated_packet_contains_beacon_layer():
    """
    Frame builder output must contain a Dot11Beacon layer.
    """

    packet = build_attack_frame(
        ssid=TEST_SSID,
        bssid=TEST_BSSID,
        channel=TEST_CHANNEL,
        seq_num=100,
        bssid_clone=True,
    )

    assert packet.haslayer(
        Dot11Beacon
    )
