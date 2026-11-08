import pytest

from backend.oj_modules.ranking.reverse_judge import settings


@pytest.mark.parametrize('value', [None, True, False, 0, 59, 7201, 1800.5, '30.5', '1e3', '１２３', ''])
def test_quality_gate_time_rejects_invalid_or_out_of_range_values(value):
    with pytest.raises(ValueError, match='60 到 7200'):
        settings.normalize_quality_gate_timeout(value)


@pytest.mark.parametrize('value, expected', [(60, 60), (' 1800 ', 1800), (7200, 7200)])
def test_quality_gate_time_accepts_integer_seconds(value, expected):
    assert settings.normalize_quality_gate_timeout(value) == expected


def test_competition_time_overrides_default_and_missing_time_uses_thirty_minutes(monkeypatch):
    monkeypatch.setattr(settings.config, 'REVERSE_QUALITY_GATE_TIMEOUT_SECONDS', 1800)
    assert settings.quality_gate_timeout_seconds({}) == 1800
    assert settings.quality_gate_timeout_seconds({'reverse_quality_gate_timeout_seconds': 4200}) == 4200
