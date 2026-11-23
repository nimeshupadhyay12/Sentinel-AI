"""The risk-score breakdown must be complete (sums to the score) and exact."""
from itertools import permutations

import numpy as np
import pytest

from app.ml.feature_pipeline import FEATURE_ORDER
from app.services.orchestrator import orchestrator

VECTORS = [
    dict(login_hour=11., files_accessed=12., sensitive_files_accessed=0., bytes_transferred_mb=10.,
         failed_logins=0., privilege_level=0., session_duration_min=180.),
    dict(login_hour=3., files_accessed=70., sensitive_files_accessed=12., bytes_transferred_mb=1300.,
         failed_logins=4., privilege_level=2., session_duration_min=430.),
    dict(login_hour=17., files_accessed=33., sensitive_files_accessed=3., bytes_transferred_mb=175.,
         failed_logins=1., privilege_level=1., session_duration_min=123.),
    dict(login_hour=22.5, files_accessed=5., sensitive_files_accessed=5., bytes_transferred_mb=301.,
         failed_logins=0., privilege_level=0., session_duration_min=30.),
]


def _explain(vector):
    scaled = orchestrator.feature_pipeline.transform(vector)
    result = orchestrator.ml_engine.evaluate(scaled)
    risk = orchestrator.ml_engine.compute_risk_score(result['iforest_score'], result['ocsvm_score'], vector)
    return scaled, result, risk, orchestrator.risk_explainer.explain(scaled, vector, risk)


@pytest.mark.parametrize('vector', VECTORS)
def test_breakdown_sums_to_the_risk_score(vector):
    _, result, risk, breakdown = _explain(vector)
    parts = breakdown['components']
    # Component points add up to the score...
    total = parts['isolation_forest']['points'] + parts['one_class_svm']['points'] + parts['rules']['points']
    assert total == pytest.approx(risk, abs=0.01)
    # ...and baseline + per-feature contributions add up to it as well.
    assert breakdown['baseline'] + sum(breakdown['by_feature'].values()) == pytest.approx(risk, abs=0.02)
    assert breakdown['reconstructed_score'] == pytest.approx(risk, abs=0.01)
    # The IF and OCSVM points are exactly the ones the score formula used.
    engine = orchestrator.ml_engine
    assert parts['isolation_forest']['points'] == pytest.approx(float(engine.if_points(result['iforest_score'])), abs=1e-3)
    assert parts['one_class_svm']['points'] == pytest.approx(float(engine.oc_points(result['ocsvm_score'])), abs=1e-3)
    for name in ('isolation_forest', 'one_class_svm'):
        part = parts[name]
        assert part['baseline'] + sum(part['contributions'].values()) == pytest.approx(part['points'], abs=0.01)


def test_rules_are_listed_and_attributed_to_their_feature():
    vector = VECTORS[3]  # 22:30, 5 sensitive files, 301 MB -> all three rules fire
    _, _, _, breakdown = _explain(vector)
    fired = {rule['rule']: rule for rule in breakdown['components']['rules']['fired']}
    assert set(fired) == {'large_transfer', 'many_sensitive_files', 'off_hours_login'}
    assert breakdown['components']['rules']['points'] == 30.0
    model_part = {f: breakdown['components']['isolation_forest']['contributions'][f]
                  + breakdown['components']['one_class_svm']['contributions'][f] for f in FEATURE_ORDER}
    assert breakdown['by_feature']['bytes_transferred_mb'] == pytest.approx(model_part['bytes_transferred_mb'] + 15, abs=0.002)
    assert breakdown['by_feature']['failed_logins'] == pytest.approx(model_part['failed_logins'], abs=0.002)
    benign = _explain(VECTORS[0])[3]
    assert benign['components']['rules']['fired'] == []


def test_shapley_weights_match_brute_force_over_all_orderings():
    scaled, _, _, _ = _explain(VECTORS[1])
    explainer = orchestrator.risk_explainer
    values, _ = explainer._coalition_values(np.asarray(scaled).reshape(-1))
    d = explainer.d
    brute = np.zeros(d)
    orderings = list(permutations(range(d)))
    for order in orderings:
        mask = 0
        for feature in order:
            brute[feature] += values[mask | (1 << feature)] - values[mask]
            mask |= 1 << feature
    brute /= len(orderings)
    assert np.allclose(explainer._shapley(values), brute, atol=1e-9)


def test_api_returns_and_stores_breakdown_for_alerts(client, analyst_headers):
    response = client.post('/api/activities/analyze', json=VECTORS[1], headers=analyst_headers)
    assert response.status_code == 200, response.text
    assessment = response.json()['assessment']
    breakdown = assessment['score_breakdown']
    assert breakdown['baseline'] + sum(breakdown['by_feature'].values()) == pytest.approx(assessment['risk_score'], abs=0.02)
    assert assessment['risk_score'] >= 50  # this vector raises an alert
    alert = client.get('/api/alerts/', headers=analyst_headers).json()[0]
    assert alert['risk_score'] == assessment['risk_score']
    assert alert['score_breakdown']['by_feature'] == breakdown['by_feature']
    assert alert['triggering_factors'] == breakdown['by_feature']
    stats = client.get('/api/analytics/dashboard-stats', headers=analyst_headers).json()
    assert stats['latest_assessment']['score_breakdown']['by_feature'] == breakdown['by_feature']


def test_one_class_models_learn_normal_behaviour_only():
    # Regression: when the live models were fitted on rows that included the
    # synthetic attacks, the OCSVM gave this blatant exfiltration 0/30 points.
    _, _, attack_risk, attack = _explain(VECTORS[1])
    assert attack['components']['one_class_svm']['points'] >= 20
    assert attack_risk >= 75
    _, _, benign_risk, _ = _explain(VECTORS[0])
    assert benign_risk < 30
