import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

# The live 0-100 risk score is the sum of three bounded parts:
#   Isolation Forest points (0-40) + One-Class SVM points (0-30) + rule points (0-30).
IF_MAX_POINTS = 40.0
OCSVM_MAX_POINTS = 30.0
# (rule id, feature, human description, points, predicate on the raw value)
RISK_RULES = (
    ("large_transfer", "bytes_transferred_mb", "More than 300 MB transferred", 15.0, lambda v: v > 300),
    ("many_sensitive_files", "sensitive_files_accessed", "5 or more sensitive files accessed", 10.0, lambda v: v >= 5),
    ("off_hours_login", "login_hour", "Activity before 06:00 or after 21:00", 5.0, lambda v: v < 6 or v > 21),
)
RULE_DEFAULTS = {"bytes_transferred_mb": 0.0, "sensitive_files_accessed": 0.0, "login_hour": 12.0}


class AnomalyDetectionEngine:
    def __init__(self):
        # Both models are fitted on a clean (benign-only) baseline, so the
        # expected outlier fraction in that baseline is small.
        self.iforest = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42
        )
        self.ocsvm = OneClassSVM(
            kernel="rbf",
            gamma="scale",
            nu=0.02
        )
        self.is_trained = False

    def train(self, X_train: np.ndarray):
        self.iforest.fit(X_train)
        self.ocsvm.fit(X_train)
        self.is_trained = True

    def evaluate(self, X: np.ndarray):
        if not self.is_trained:
            raise RuntimeError("Anomaly models must be trained before evaluation.")

        # Decision function: lower scores indicate higher anomalousness
        if_raw = self.iforest.decision_function(X)
        oc_raw = self.ocsvm.decision_function(X)

        if_pred = self.iforest.predict(X)  # -1 = anomaly, 1 = normal
        oc_pred = self.ocsvm.predict(X)

        return {
            "iforest_score": float(if_raw[0]),
            "ocsvm_score": float(oc_raw[0]),
            "iforest_anomaly": bool(if_pred[0] == -1),
            "ocsvm_anomaly": bool(oc_pred[0] == -1)
        }

    # --- Score components (vectorised so the explainer can call them in bulk) ---
    @staticmethod
    def if_points(if_score):
        """Map IF decision values (about -0.3..+0.3, lower = more anomalous) to 0-40 points."""
        return np.clip((0.25 - np.asarray(if_score, dtype=float)) / 0.50, 0.0, 1.0) * IF_MAX_POINTS

    @staticmethod
    def oc_points(oc_score):
        """Map OCSVM decision values (lower = more anomalous) to 0-30 points."""
        return np.clip((0.25 - np.asarray(oc_score, dtype=float)) / 0.50, 0.0, 1.0) * OCSVM_MAX_POINTS

    @staticmethod
    def fired_rules(raw_features: dict) -> list[dict]:
        """Heuristic exfiltration indicators that add fixed points (max 30 in total)."""
        fired = []
        for rule_id, feature, description, points, predicate in RISK_RULES:
            value = float(raw_features.get(feature, RULE_DEFAULTS[feature]))
            if predicate(value):
                fired.append({"rule": rule_id, "feature": feature, "description": description,
                              "value": value, "points": points})
        return fired

    @classmethod
    def compute_risk_score(cls, if_score: float, oc_score: float, raw_features: dict) -> float:
        """0-100 risk = IF points (0-40) + OCSVM points (0-30) + rule points (0-30)."""
        penalties = sum(rule["points"] for rule in cls.fired_rules(raw_features))
        total = float(cls.if_points(if_score)) + float(cls.oc_points(oc_score)) + penalties
        # The parts are non-negative and their maxima add up to exactly 100, so
        # the clip never changes the value; it is kept as a guard.
        return round(float(np.clip(total, 0.0, 100.0)), 2)
