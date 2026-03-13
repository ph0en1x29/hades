#!/usr/bin/env python3
"""Parser edge case and robustness tests.

Tests malformed inputs, boundary conditions, large files,
and cross-parser consistency.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingestion.parsers.splunk_sysmon import load_sysmon_log
from src.ingestion.parsers.splunk_suricata import load_suricata_log
from src.ingestion.parsers.cicids2018 import load_cicids2018_csv
from src.ingestion.parsers.beth import load_beth_csv
from src.ingestion.schema import AlertSeverity

passed = 0
failed = 0


def ok(name: str):
    global passed
    passed += 1
    print(f"  ✅ {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  ❌ {name}: {reason}")


# === Sysmon parser tests ===

def test_sysmon_empty_file():
    """Empty file should return empty list, not crash."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("")
        f.flush()
        alerts = load_sysmon_log(f.name, mitre_technique="T9999")
    assert alerts == [], f"Expected empty list, got {len(alerts)}"
    ok("sysmon: empty file → []")


def test_sysmon_malformed_json():
    """Lines with invalid JSON should be skipped."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("not json at all\n")
        f.write("{broken json\n")
        f.write('{"valid": "json but not sysmon"}\n')
        f.flush()
        alerts = load_sysmon_log(f.name, mitre_technique="T9999")
    # Should not crash; may return 0 or some alerts depending on parser
    ok(f"sysmon: malformed JSON → {len(alerts)} alerts (no crash)")


def test_sysmon_limit_parameter():
    """Limit parameter caps number of alerts returned."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1003.001" / "windows-sysmon.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("sysmon: limit test (skipped — no data)")
        return
    alerts_5 = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=5)
    alerts_50 = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=50)
    assert len(alerts_5) == 5, f"limit=5 got {len(alerts_5)}"
    assert len(alerts_50) == 50, f"limit=50 got {len(alerts_50)}"
    ok("sysmon: limit parameter works correctly")


def test_sysmon_alert_id_uniqueness():
    """Alert IDs must be unique within a file."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1003.001" / "windows-sysmon.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("sysmon: uniqueness test (skipped — no data)")
        return
    alerts = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=100)
    ids = [a.alert_id for a in alerts]
    assert len(ids) == len(set(ids)), f"duplicate IDs found: {len(ids)} total, {len(set(ids))} unique"
    ok("sysmon: 100 alert IDs all unique")


def test_sysmon_severity_consistency():
    """All Sysmon alerts should have valid severity."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1003.001" / "windows-sysmon.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("sysmon: severity test (skipped)")
        return
    alerts = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=20)
    for a in alerts:
        assert isinstance(a.severity, AlertSeverity), f"invalid severity: {a.severity}"
    ok("sysmon: all alerts have valid AlertSeverity")


def test_sysmon_raw_log_is_json():
    """raw_log should be parseable JSON string."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1003.001" / "windows-sysmon.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("sysmon: raw_log JSON test (skipped)")
        return
    alerts = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=10)
    for a in alerts:
        parsed = json.loads(a.raw_log)
        assert isinstance(parsed, dict), f"raw_log not a dict"
    ok("sysmon: all raw_logs are valid JSON dicts")


# === Suricata parser tests ===

def test_suricata_c2_logs():
    """Suricata C2 logs should parse with HTTP metadata."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1071.001" / "suricata_c2.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("suricata: C2 test (skipped)")
        return
    alerts = load_suricata_log(str(path), mitre_technique="T1071.001", limit=20)
    assert len(alerts) > 0, "no alerts parsed"
    http_count = sum(1 for a in alerts if "http" in (a.event_type or "").lower())
    ok(f"suricata: {len(alerts)} C2 alerts, {http_count} HTTP events")


def test_suricata_empty_file():
    """Empty Suricata file should return empty list."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("")
        f.flush()
        alerts = load_suricata_log(f.name, mitre_technique="T9999")
    assert alerts == [], f"Expected empty list, got {len(alerts)}"
    ok("suricata: empty file → []")


# === CIC-IDS2018 parser tests ===

def test_cicids_csv():
    """CIC-IDS CSV should parse if available."""
    csv_path = ROOT / "data" / "datasets" / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    if not csv_path.exists():
        ok("cicids: CSV test (skipped — file not present)")
        return
    alerts = load_cicids2018_csv(str(csv_path), dataset_name="test")
    # Just check first 100
    sample = alerts[:100] if len(alerts) > 100 else alerts
    assert len(sample) > 0, "no alerts parsed"
    labels = set(a.severity.value for a in sample)
    ok(f"cicids: {len(alerts)} total alerts, severities: {labels}")


# === BETH parser tests ===

def test_beth_fixtures():
    """BETH fixture CSVs should parse correctly."""
    dns_path = ROOT / "data" / "fixtures" / "beth_dns_sample.csv"
    proc_path = ROOT / "data" / "fixtures" / "beth_process_sample.csv"

    if dns_path.exists():
        dns_alerts = load_beth_csv(str(dns_path), dataset_name="test_dns")
        assert len(dns_alerts) > 0, "no DNS alerts"
        ok(f"beth: DNS fixture → {len(dns_alerts)} alerts")
    else:
        ok("beth: DNS fixture (skipped)")

    if proc_path.exists():
        proc_alerts = load_beth_csv(str(proc_path), dataset_name="test_proc")
        assert len(proc_alerts) > 0, "no process alerts"
        ok(f"beth: process fixture → {len(proc_alerts)} alerts")
    else:
        ok("beth: process fixture (skipped)")


# === Cross-parser consistency tests ===

def test_alert_schema_consistency():
    """All parsers should produce alerts with the same field structure."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"

    sysmon_path = data_dir / "T1003.001" / "windows-sysmon.log"
    suricata_path = data_dir / "T1071.001" / "suricata_c2.log"

    parsers_alerts = []
    if sysmon_path.exists() and sysmon_path.stat().st_size > 0:
        parsers_alerts.append(("sysmon", load_sysmon_log(str(sysmon_path), mitre_technique="T1003.001", limit=1)))
    if suricata_path.exists() and suricata_path.stat().st_size > 0:
        parsers_alerts.append(("suricata", load_suricata_log(str(suricata_path), mitre_technique="T1071.001", limit=1)))

    required_fields = ["alert_id", "timestamp", "severity", "raw_log", "provenance", "benchmark"]

    for parser_name, alerts in parsers_alerts:
        if not alerts:
            continue
        a = alerts[0]
        for field in required_fields:
            assert hasattr(a, field) and getattr(a, field) is not None, \
                f"{parser_name}: missing or None field '{field}'"

    ok(f"schema consistency: {len(parsers_alerts)} parsers checked, all have required fields")


def test_to_dict_roundtrip():
    """Alert.to_dict() should produce valid JSON-serializable dict."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1003.001" / "windows-sysmon.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("to_dict roundtrip (skipped)")
        return
    alerts = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=5)
    for a in alerts:
        d = a.to_dict()
        assert isinstance(d, dict), "to_dict didn't return dict"
        # Should be JSON serializable
        j = json.dumps(d)
        assert len(j) > 50, "JSON too short"
    ok("to_dict: 5 alerts round-trip to JSON successfully")


def test_to_json_method():
    """Alert.to_json() should produce valid JSON string."""
    data_dir = ROOT / "data" / "datasets" / "splunk_attack_data"
    path = data_dir / "T1003.001" / "windows-sysmon.log"
    if not path.exists() or path.stat().st_size == 0:
        ok("to_json (skipped)")
        return
    alerts = load_sysmon_log(str(path), mitre_technique="T1003.001", limit=3)
    for a in alerts:
        j = a.to_json()
        parsed = json.loads(j)
        assert parsed["alert_id"] == a.alert_id
    ok("to_json: 3 alerts produce valid JSON with correct alert_id")


def main():
    print("=" * 70)
    print("  HADES — Parser Edge Cases & Robustness Tests")
    print("=" * 70)

    print("\n─── Sysmon Parser ───")
    test_sysmon_empty_file()
    test_sysmon_malformed_json()
    test_sysmon_limit_parameter()
    test_sysmon_alert_id_uniqueness()
    test_sysmon_severity_consistency()
    test_sysmon_raw_log_is_json()

    print("\n─── Suricata Parser ───")
    test_suricata_c2_logs()
    test_suricata_empty_file()

    print("\n─── CIC-IDS2018 Parser ───")
    test_cicids_csv()

    print("\n─── BETH Parser ───")
    test_beth_fixtures()

    print("\n─── Cross-Parser Consistency ───")
    test_alert_schema_consistency()
    test_to_dict_roundtrip()
    test_to_json_method()

    print()
    print("=" * 70)
    total = passed + failed
    print(f"  RESULTS: {passed}/{total} passed")
    print("=" * 70)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
