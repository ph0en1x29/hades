from pathlib import Path

from src.ingestion.parsers import load_beth_csv


FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures"


def test_load_beth_dns_csv() -> None:
    alerts = load_beth_csv(FIXTURES / "beth_dns_sample.csv")
    assert len(alerts) == 2
    assert alerts[0].event_type == "beth_dns"
    assert alerts[0].protocol == "dns"
    assert alerts[0].benchmark.rule_source == "beth_labels"
    assert alerts[0].provenance.dataset_role.value == "engineering_scaffold"
    assert alerts[0].severity.value == "medium"


def test_load_beth_process_csv() -> None:
    alerts = load_beth_csv(FIXTURES / "beth_process_sample.csv")
    assert len(alerts) == 3
    assert alerts[0].event_type == "beth_process"
    assert alerts[0].metadata.category == "process"
    assert alerts[0].severity.value == "info"
    assert alerts[1].severity.value == "medium"
    assert alerts[2].severity.value == "high"
