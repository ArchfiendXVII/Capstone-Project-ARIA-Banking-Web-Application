from __future__ import annotations

from compliance.checks import CHECK_REGISTRY, run_checks
from compliance.collector import collect_signals


def test_registry_has_22_checks():
    assert len(CHECK_REGISTRY) >= 22


def test_each_check_returns_valid_shape():
    ctx = collect_signals()
    results = run_checks(ctx)
    assert len(results) >= 22
    for result in results:
        assert result.check_id
        assert result.status in ("pass", "fail", "partial", "not_tested")
        assert isinstance(result.evidence, str)
        assert isinstance(result.finding_ids, list)
        assert isinstance(result.standards, list)
