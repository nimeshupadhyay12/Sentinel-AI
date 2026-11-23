from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.ml.generator import SyntheticDataGenerator
from app.ml.feature_pipeline import FeatureEngineeringPipeline
from app.ml.models import AnomalyDetectionEngine
from app.ml.explainer import ModelExplainer
from app.ml.game_engine import AdaptiveStackelbergGameEngine
from app.models.models import ThreatAnalysisRecord, Alert, Incident, ResearchInteraction
from app.services.audit import append_audit_record, append_lock, verify_audit_chain

class SentinelOrchestrator:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SentinelOrchestrator, cls).__new__(cls)
            cls._instance.initialize_pipeline()
        return cls._instance

    def initialize_pipeline(self):
        self.generator = SyntheticDataGenerator(seed=42)
        self.feature_pipeline = FeatureEngineeringPipeline()
        self.ml_engine = AnomalyDetectionEngine()
        self.game_engine = AdaptiveStackelbergGameEngine()

        # Bootstrap training
        df_train = self.generator.generate_baseline_dataset(n_samples=1000)
        X_train_scaled = self.feature_pipeline.fit_transform(df_train)
        self.ml_engine.train(X_train_scaled)
        self.explainer = ModelExplainer(self.ml_engine.iforest, X_train_scaled)

    def analyze_event(self, user_id: int, raw_features: dict, db: Session) -> dict:
        # 1. Feature Transformation & 2. ML Detection
        scaled_sample = self.feature_pipeline.transform(raw_features)
        eval_results = self.ml_engine.evaluate(scaled_sample)

        # 3. Normalized Risk Scoring
        risk_score = self.ml_engine.compute_risk_score(
            eval_results["iforest_score"],
            eval_results["ocsvm_score"],
            raw_features
        )
        shap_scores = self.explainer.explain(scaled_sample)

        # =====================================================================
        # PART 2 RESEARCH: STEP 8 (THE FEEDBACK LOOP)
        # =====================================================================
        # Fetch previous turn to establish baseline
        prev_record = db.query(ThreatAnalysisRecord)\
            .filter(ThreatAnalysisRecord.user_id == user_id)\
            .order_by(ThreatAnalysisRecord.timestamp.desc(), ThreatAnalysisRecord.id.desc()).first()

        prev_features = prev_record.raw_features if prev_record else {}
        prev_action = prev_record.game_action if prev_record else "UNKNOWN"
        prev_risk = prev_record.risk_score if prev_record else 0.0

        # Step 3: Attacker State
        state_probs = self.game_engine.calculate_attacker_state_probs(raw_features)
        dominant_state = max(state_probs, key=state_probs.get)

        # Step 4: Attacker Adaptation Score (AAS)
        aas = self.game_engine.calculate_adaptation_score(raw_features, prev_features, prev_action)

        # Step 5: Response Effectiveness Score (RES)
        effectiveness = self.game_engine.metrics.effectiveness(
            risk_score, prev_risk, raw_features, prev_features, prev_action)
        res = effectiveness['score']

        # Step 7: Dynamic Payoff & Action Selection
        game_decision = self.game_engine.resolve_optimal_defense(risk_score, dominant_state, aas, res, prev_action, effectiveness["available"])
        action = game_decision["selected_action"]
        # =====================================================================

        # 6. Persistent Threat Record
        threat_record = ThreatAnalysisRecord(
            user_id=user_id,
            raw_features=raw_features,
            iforest_score=eval_results["iforest_score"],
            ocsvm_score=eval_results["ocsvm_score"],
            risk_score=risk_score,
            shap_attributions=shap_scores,
            game_action=action,
            attacker_state_probs=state_probs,
            adaptation_score=aas,
            response_effectiveness=res,
            attacker_state=dominant_state
        )
        db.add(threat_record)
        db.flush()
        db.add(ResearchInteraction(
            threat_record_id=threat_record.id, user_id=user_id,
            previous_behaviour=prev_features, current_behaviour=raw_features,
            previous_defence=prev_action, previous_risk=prev_risk,
            current_risk=risk_score, current_attacker_state=dominant_state,
            aas=aas, res=res, res_available=effectiveness['available'],
            res_components=effectiveness['components'], game_details=game_decision,
        ))

        # 7. Automated Alert & Incident Triggering
        if risk_score >= 50.0:
            alert = Alert(
                user_id=user_id,
                severity="CRITICAL" if risk_score > 80 else "HIGH" if risk_score > 65 else "MEDIUM",
                risk_score=risk_score,
                triggering_factors=shap_scores,
                recommended_action=action
            )
            db.add(alert)

        if risk_score >= 75.0:
            incident = Incident(
                title=f"Automated Alert: High-Risk {dominant_state} Detected for User {user_id}",
                user_id=user_id,
                risk_score=risk_score,
                shap_summary=shap_scores,
                enforced_action=action,
                status="OPEN"
            )
            db.add(incident)

        # Tamper-evident audit record (Ed25519-signed, chained). Failing to seal
        # the record fails the request: a decision must not go unaudited.
        with append_lock:
            append_audit_record(db, {
                "user_id": user_id,
                "risk_score": float(risk_score),
                "game_action": action,
                "attacker_state": dominant_state,
                "adaptation_score": float(aas),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            db.commit()

        return {
            "user_id": user_id,
            "risk_score": risk_score,
            "iforest_anomaly": eval_results["iforest_anomaly"],
            "ocsvm_anomaly": eval_results["ocsvm_anomaly"],
            "game_action": action,
            "top_explanations": shap_scores,
            "adaptive_metrics": {
                "attacker_state": dominant_state,
                "state_probabilities": state_probs,
                "adaptation_score_aas": aas,
                "response_effectiveness_res": res,
                "res_available": effectiveness["available"],
                "res_components": effectiveness["components"],
                "previous_defence": prev_action
            },
            "details": {
                "decision_distribution": game_decision["action_distribution"],
                "utility": game_decision["expected_utility"],
                "iforest_metric": eval_results["iforest_score"],
                "ocsvm_metric": eval_results["ocsvm_score"]
            }
        }

    def verify_audit_chain(self, db: Session) -> dict:
        """Kept for compatibility; see app.services.audit.verify_audit_chain."""
        return verify_audit_chain(db)


orchestrator = SentinelOrchestrator()
