"""Explanations for the live detector.

Two complementary views:

* ``ModelExplainer`` - TreeSHAP on the Isolation Forest in the model's own
  output space (average path length; negative = shorter path = more anomalous).
  Kept for continuity with earlier versions (``shap_attributions``).

* ``RiskScoreExplainer`` - a complete, additive breakdown of the 0-100 risk
  score that the dashboard and alerts show:

      risk = baseline + sum over features of (IF Shapley + OCSVM Shapley + rule points)

  The Isolation Forest and One-Class SVM parts are exact interventional
  Shapley values (the quantity SHAP's KernelExplainer estimates) of the *points*
  each model contributes, computed by evaluating all 2^7 = 128 feature
  coalitions against a small fixed background sample, so no sampling error.
  Rule points are attributed in full to the single feature each rule tests.
  ``baseline`` is the average model points of the background sample, i.e. what
  a typical normal session scores.
"""
import logging
from math import factorial

import numpy as np

try:
    import shap
    HAS_SHAP = True
except ImportError:
    shap = None
    HAS_SHAP = False

from app.ml.feature_pipeline import FEATURE_ORDER
from app.ml.models import IF_MAX_POINTS, OCSVM_MAX_POINTS, AnomalyDetectionEngine

logger = logging.getLogger("sentinel.explainer")


class ModelExplainer:
    def __init__(self, model, background_data: np.ndarray):
        self.explainer = None
        if HAS_SHAP:
            try:
                self.explainer = shap.TreeExplainer(model, background_data[:100])
            except Exception as e:
                logger.warning("Failed to initialize TreeExplainer: %s", e)

    def explain(self, sample: np.ndarray) -> dict[str, float]:
        attribution = {}
        if self.explainer is not None:
            try:
                shap_values = self.explainer.shap_values(sample)
                vals = shap_values[0] if len(shap_values.shape) > 1 else shap_values
                for idx, col in enumerate(FEATURE_ORDER):
                    attribution[col] = round(float(vals[idx]), 4)
                return attribution
            except Exception as e:
                logger.warning("SHAP explanation failed: %s", e)

        # Fallback attribution based on normalized feature deviation
        sample_vals = sample.flatten() if hasattr(sample, 'flatten') else sample
        for idx, col in enumerate(FEATURE_ORDER):
            val = float(sample_vals[idx]) if idx < len(sample_vals) else 0.0
            attribution[col] = round(val * 0.1, 4)
        return attribution


class RiskScoreExplainer:
    """Exact additive decomposition of ``AnomalyDetectionEngine.compute_risk_score``."""

    def __init__(self, engine: AnomalyDetectionEngine, training_scaled: np.ndarray,
                 n_background: int = 20, seed: int = 0):
        self.engine = engine
        self.d = training_scaled.shape[1]
        # Background = training rows that BOTH models consider normal, so the
        # baseline means "a typical normal session", not an average that
        # includes the synthetic attacks present in the training set.
        inliers = training_scaled[(engine.iforest.predict(training_scaled) == 1)
                                  & (engine.ocsvm.predict(training_scaled) == 1)]
        pool = inliers if len(inliers) >= n_background else training_scaled
        rng = np.random.default_rng(seed)
        self.background = pool[rng.choice(len(pool), size=min(n_background, len(pool)), replace=False)]

        masks = np.arange(2 ** self.d)
        # bits[m, i] is True when feature i is "present" (taken from the sample) in coalition m.
        self.bits = ((masks[:, None] >> np.arange(self.d)) & 1).astype(bool)
        sizes = self.bits.sum(axis=1)
        # Shapley weight |S|!(d-|S|-1)!/d! for adding a feature to a coalition of size |S|.
        self.weights = np.array([factorial(s) * factorial(self.d - s - 1) / factorial(self.d)
                                 if s < self.d else 0.0 for s in sizes])

    def _coalition_values(self, x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Mean IF and OCSVM points for every coalition (features outside S come from the background)."""
        rows = np.where(self.bits[:, None, :], x[None, None, :], self.background[None, :, :])
        flat = rows.reshape(-1, self.d)
        n_masks, n_bg = self.bits.shape[0], self.background.shape[0]
        if_v = self.engine.if_points(self.engine.iforest.decision_function(flat)).reshape(n_masks, n_bg).mean(1)
        oc_v = self.engine.oc_points(self.engine.ocsvm.decision_function(flat)).reshape(n_masks, n_bg).mean(1)
        return if_v, oc_v

    def _shapley(self, values: np.ndarray) -> np.ndarray:
        phi = np.zeros(self.d)
        for i in range(self.d):
            without = ~self.bits[:, i]
            masks = np.flatnonzero(without)
            phi[i] = np.sum(self.weights[masks] * (values[masks | (1 << i)] - values[masks]))
        return phi

    def explain(self, sample_scaled: np.ndarray, raw_features: dict, risk_score: float) -> dict:
        x = np.asarray(sample_scaled, dtype=float).reshape(-1)[: self.d]
        if_v, oc_v = self._coalition_values(x)
        full, empty = 2 ** self.d - 1, 0
        if_phi, oc_phi = self._shapley(if_v), self._shapley(oc_v)
        rules = self.engine.fired_rules(raw_features)
        rule_by_feature = {f: 0.0 for f in FEATURE_ORDER}
        for rule in rules:
            rule_by_feature[rule["feature"]] += rule["points"]

        baseline = float(if_v[empty] + oc_v[empty])
        by_feature = {f: float(if_phi[i] + oc_phi[i] + rule_by_feature[f]) for i, f in enumerate(FEATURE_ORDER)}
        reconstructed = baseline + sum(by_feature.values())
        r = lambda v: round(float(v), 3)  # noqa: E731
        return {
            "method": ("exact interventional Shapley values over all 128 feature coalitions "
                       f"({len(self.background)}-row normal background) for the IF and OCSVM points; "
                       "rule points listed and attributed to the feature each rule tests"),
            "risk_score": float(risk_score),
            "baseline": r(baseline),
            "components": {
                "isolation_forest": {"points": r(if_v[full]), "max_points": IF_MAX_POINTS,
                                     "baseline": r(if_v[empty]),
                                     "contributions": {f: r(if_phi[i]) for i, f in enumerate(FEATURE_ORDER)}},
                "one_class_svm": {"points": r(oc_v[full]), "max_points": OCSVM_MAX_POINTS,
                                  "baseline": r(oc_v[empty]),
                                  "contributions": {f: r(oc_phi[i]) for i, f in enumerate(FEATURE_ORDER)}},
                "rules": {"points": r(sum(rule["points"] for rule in rules)), "max_points": 30.0,
                          "fired": rules},
            },
            "by_feature": {f: r(v) for f, v in by_feature.items()},
            # baseline + sum(by_feature) equals the risk score up to rounding.
            "reconstructed_score": r(reconstructed),
        }
