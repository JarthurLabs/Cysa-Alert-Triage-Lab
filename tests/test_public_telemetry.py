import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from validate_public_telemetry import (  # noqa: E402
    EXPECTED_SHA256,
    build_summary,
    is_explorer_child_candidate,
    is_tuned_encoded_powershell,
    load_events,
    sha256_file,
)


LOG = ROOT / "data/public/splunk_attack_data/explorer_spawns_windows-sysmon.log"


class PublicTelemetryTests(unittest.TestCase):
    def test_integrity_matches_pinned_upstream_object(self):
        self.assertEqual(sha256_file(LOG), EXPECTED_SHA256)

    def test_four_sysmon_process_creation_events_parse(self):
        events = load_events(LOG)
        self.assertEqual(len(events), 4)
        self.assertEqual({event.event_id for event in events}, {1})
        self.assertEqual({event.computer for event in events}, {"ar-win-3"})

    def test_detection_tuning_reduces_four_candidates_to_two(self):
        events = load_events(LOG)
        broad = [event for event in events if is_explorer_child_candidate(event)]
        tuned = [event for event in broad if is_tuned_encoded_powershell(event)]
        self.assertEqual(len(broad), 4)
        self.assertEqual(len(tuned), 2)

    def test_summary_records_two_lower_confidence_exclusions(self):
        summary = build_summary(LOG)
        self.assertTrue(summary["integrity_verified"])
        self.assertEqual(summary["lower_confidence_candidates_excluded"], 2)


if __name__ == "__main__":
    unittest.main()
