"""The summariser is the only non-trivial logic here, so it is what gets tested."""

import pytest

from pydantic_ai_trustabl import summarize_scan


def _finding(rule_id, severity, origin=None, path='src/app.py'):
    f = {
        'rule_id': rule_id,
        'severity': severity,
        'title': f'{rule_id} title',
        'file_path': path,
        'start_line': 1,
        'explanation': '',
        'suggested_fix': '',
    }
    if origin is not None:
        f['origin'] = origin
    return f


def test_test_findings_are_excluded_from_counts_and_findings():
    """A histogram that counted test findings would contradict the findings beside it."""
    raw = {
        'findings': [
            _finding('A', 'critical'),
            _finding('B', 'critical', origin='test', path='tests/test_app.py'),
            _finding('C', 'high'),
        ]
    }
    out = summarize_scan(raw, severity_floor='info')

    assert out.by_severity == {'critical': 1, 'high': 1}
    assert out.total_findings == 2
    assert out.excluded_test_findings == 1
    assert [f.rule_id for f in out.findings] == ['A', 'C']


def test_counts_cover_every_production_finding_even_below_the_floor():
    raw = {'findings': [_finding('A', 'critical'), _finding('B', 'low'), _finding('C', 'info')]}
    out = summarize_scan(raw, severity_floor='high')

    assert out.by_severity == {'critical': 1, 'low': 1, 'info': 1}
    assert out.total_findings == 3
    assert out.below_severity_floor == 2
    assert [f.rule_id for f in out.findings] == ['A']
    assert out.truncated is False


def test_truncation_keeps_the_worst_and_flags_itself():
    raw = {'findings': [_finding(f'R{i}', 'low') for i in range(5)] + [_finding('WORST', 'critical')]}
    out = summarize_scan(raw, severity_floor='low', max_findings=2)

    assert out.truncated is True
    assert out.findings[0].rule_id == 'WORST'
    assert len(out.findings) == 2
    assert out.total_findings == 6


def test_null_sdks_does_not_crash():
    """The scanner emits `sdks: null`, not `[]`, on a repo with none."""
    out = summarize_scan({'findings': [], 'sdks': None})
    assert out.inventory.sdks == []
    assert out.by_severity == {}


def test_empty_report_is_not_an_error():
    out = summarize_scan({})
    assert out.total_findings == 0
    assert out.truncated is False


def test_bad_severity_floor_is_rejected():
    with pytest.raises(ValueError):
        summarize_scan({'findings': []}, severity_floor='catastrophic')
