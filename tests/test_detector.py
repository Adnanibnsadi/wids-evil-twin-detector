"""
Unit tests for the hybrid WIDS decision engine.

These tests exercise detector.evaluate_packet() directly.

They do not:

- capture wireless traffic
- transmit packets
- require root privileges
- require monitor mode
- require trained model files on disk

Small fake scaler/model objects are used where needed to
test the Isolation Forest integration path.
"""

import pytest

from modules import detector


PROFILE_BSSID = "02:10:00:00:00:01"
ROGUE_BSSID = "02:10:00:00:00:99"
UNKNOWN_BSSID = "02:10:00:00:00:50"

TEST_SSID = "LAB_AP_01"


class IdentityScaler:
    """
    Minimal test double for a scikit-learn scaler.

    It returns the supplied feature matrix unchanged.
    """

    def transform(
        self,
        values,
    ):
        return values


class FixedScoreModel:
    """
    Minimal test double for an Isolation Forest model.

    decision_function() always returns the configured
    anomaly score.
    """

    def __init__(
        self,
        score,
    ):
        self.score = score

    def decision_function(
        self,
        values,
    ):
        return [
            self.score,
        ]


@pytest.fixture(autouse=True)
def reset_detector_state():
    """
    Ensure detector global state cannot leak between tests.
    """

    detector.bssid_profiles.clear()
    detector.per_bssid_bundle.clear()
    detector.global_bundle.clear()

    detector.seq_tracker.clear()
    detector.ts_tracker.clear()
    detector.last_seen_seq.clear()
    detector.last_seen_bssid.clear()

    detector.alert_cooldown.clear()
    detector.suspicious_streak.clear()

    detector.packet_count = 0
    detector.alert_count = 0

    yield

    detector.bssid_profiles.clear()
    detector.per_bssid_bundle.clear()
    detector.global_bundle.clear()

    detector.seq_tracker.clear()
    detector.ts_tracker.clear()
    detector.last_seen_seq.clear()
    detector.last_seen_bssid.clear()

    detector.alert_cooldown.clear()
    detector.suspicious_streak.clear()


def install_baseline_profile():
    """
    Install one synthetic legitimate AP profile.
    """

    detector.bssid_profiles[
        PROFILE_BSSID
    ] = {
        "ssid":
            TEST_SSID,

        "bssid":
            PROFILE_BSSID,

        "ie_count":
            20,

        "rate_count":
            12,

        "security":
            "WPA2/WPA3",

        "clock_skew_mean":
            0.00001,

        "clock_skew_std":
            0.00005,
    }


def make_feature(
    **overrides,
):
    """
    Build a normal observation and optionally override
    selected feature values.
    """

    feature = {
        "ssid":
            TEST_SSID,

        "bssid":
            PROFILE_BSSID,

        "rssi":
            -55,

        "channel":
            6,

        "seq_num":
            100,

        "seq_jump":
            1,

        "seq_anomaly_score":
            0.0,

        "beacon_timestamp":
            1_000_000,

        "clock_skew":
            0.00001,

        "valid_skew":
            False,

        "beacon_interval":
            100,

        "capabilities":
            0,

        "security":
            "WPA2/WPA3",

        "security_encoded":
            3,

        "ie_count":
            20,

        "rate_count":
            12,

        "inter_beacon_ms":
            100.0,

        "is_seq_duplicate":
            0,
    }


    feature.update(
        overrides
    )


    return feature


def install_fake_anomaly_model(
    score,
):
    """
    Install a fake per-BSSID anomaly model.

    The detector's current prototype threshold is
    decision_function score < -0.12.
    """

    detector.per_bssid_bundle.update(
        {
            "features": [
                "clock_skew",
                "rssi",
                "seq_jump",
                "inter_beacon_ms",
            ],

            "models": {
                PROFILE_BSSID:
                    FixedScoreModel(
                        score
                    ),
            },

            "scalers": {
                PROFILE_BSSID:
                    IdentityScaler(),
            },
        }
    )


def test_matching_baseline_is_not_suspicious():
    """
    Observation matching the stored profile should not
    generate evidence or a positive threat score.
    """

    install_baseline_profile()

    feature = make_feature()

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is False
    assert reasons == []
    assert threat_score == 0.0


def test_unknown_unprofiled_ap_is_ignored():
    """
    An unrelated SSID/BSSID not represented in the
    baseline should currently be ignored.
    """

    install_baseline_profile()

    feature = make_feature(
        ssid="UNRELATED_AP",
        bssid=UNKNOWN_BSSID,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is False
    assert reasons == []
    assert threat_score == 0.0


def test_known_ssid_from_different_bssid_is_suspicious():
    """
    A profiled SSID appearing from a different BSSID is
    strong evidence in the current prototype.
    """

    install_baseline_profile()

    feature = make_feature(
        bssid=ROGUE_BSSID,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is True
    assert threat_score == pytest.approx(
        0.85
    )

    assert any(
        "SSID/BSSID inconsistency"
        in reason
        for reason in reasons
    )


def test_duplicate_sequence_activity_is_suspicious():
    """
    Short-interval duplicate sequence activity is strong
    suspicious evidence in the current detector.
    """

    install_baseline_profile()

    feature = make_feature(
        is_seq_duplicate=1,
        seq_num=777,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is True
    assert threat_score == pytest.approx(
        0.90
    )

    assert any(
        "Duplicate sequence activity"
        in reason
        for reason in reasons
    )


def test_large_ie_deviation_is_suspicious():
    """
    An IE-count difference of at least three is currently
    treated as strong structural evidence.
    """

    install_baseline_profile()

    feature = make_feature(
        ie_count=23,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is True
    assert threat_score == pytest.approx(
        0.70
    )

    assert any(
        "Beacon IE count deviation"
        in reason
        for reason in reasons
    )


def test_security_change_is_suspicious():
    """
    A change in the advertised security category is
    treated as strong evidence.
    """

    install_baseline_profile()

    feature = make_feature(
        security="Open",
        security_encoded=0,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is True
    assert threat_score == pytest.approx(
        0.60
    )

    assert any(
        "Advertised security change"
        in reason
        for reason in reasons
    )


def test_rate_deviation_alone_is_not_enough():
    """
    Supported-rate deviation contributes to the threat
    score but is supporting evidence rather than a strong
    standalone condition.
    """

    install_baseline_profile()

    feature = make_feature(
        rate_count=15,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is False
    assert threat_score == pytest.approx(
        0.30
    )

    assert any(
        "Supported-rate deviation"
        in reason
        for reason in reasons
    )


def test_timing_deviation_alone_is_not_enough():
    """
    A large valid timing deviation contributes supporting
    evidence but does not independently cross the current
    decision threshold.
    """

    install_baseline_profile()

    feature = make_feature(
        valid_skew=True,
        clock_skew=0.001,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is False
    assert threat_score == pytest.approx(
        0.35
    )

    assert any(
        "Timing deviation"
        in reason
        for reason in reasons
    )


def test_anomaly_model_alone_is_not_enough():
    """
    A low per-BSSID Isolation Forest decision score
    contributes evidence but should not independently
    trigger the current detector.
    """

    install_baseline_profile()

    install_fake_anomaly_model(
        score=-0.20,
    )

    feature = make_feature(
        valid_skew=True,
        clock_skew=0.00001,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is False
    assert threat_score == pytest.approx(
        0.25
    )

    assert any(
        "Per-BSSID anomaly model"
        in reason
        for reason in reasons
    )


def test_supporting_evidence_can_cross_threshold():
    """
    Multiple supporting signals may collectively cross the
    0.75 heuristic threshold even when no strong evidence
    rule is present.

    Current contributions:

    rate deviation       = 0.30
    timing deviation     = 0.35
    anomaly model        = 0.25
                           ----
                           0.90
    """

    install_baseline_profile()

    install_fake_anomaly_model(
        score=-0.20,
    )

    feature = make_feature(
        rate_count=15,
        valid_skew=True,
        clock_skew=0.001,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is True

    assert threat_score == pytest.approx(
        0.90
    )

    assert any(
        "Supported-rate deviation"
        in reason
        for reason in reasons
    )

    assert any(
        "Timing deviation"
        in reason
        for reason in reasons
    )

    assert any(
        "Per-BSSID anomaly model"
        in reason
        for reason in reasons
    )


def test_model_threshold_boundary_is_not_anomalous():
    """
    The current model rule uses score < -0.12.

    Therefore exactly -0.12 should not contribute the
    model evidence weight.
    """

    install_baseline_profile()

    install_fake_anomaly_model(
        score=-0.12,
    )

    feature = make_feature(
        valid_skew=True,
        clock_skew=0.00001,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is False
    assert threat_score == 0.0

    assert not any(
        "Per-BSSID anomaly model"
        in reason
        for reason in reasons
    )


def test_threat_score_is_capped_at_one():
    """
    Combined evidence can mathematically exceed 1.0, but
    the externally returned heuristic score must be capped
    at 1.0.
    """

    install_baseline_profile()

    feature = make_feature(
        bssid=ROGUE_BSSID,
        is_seq_duplicate=1,
        ie_count=24,
        security="Open",
        security_encoded=0,
        rate_count=16,
    )

    (
        is_suspicious,
        reasons,
        threat_score,
    ) = detector.evaluate_packet(
        feature
    )

    assert is_suspicious is True

    assert threat_score == pytest.approx(
        1.0
    )

    assert len(
        reasons
    ) >= 4
