"""
Explainability layer.

An analyst needs to know WHY an event was flagged, not just that it scored 87.
Three attribution sources are combined:

  1. baseline z-score decomposition  -- "this entity's normal range is X, this
     was Y" (always available, always interpretable)
  2. sequence autoencoder per-feature reconstruction error -- which behavioural
     dimension the model could not predict
  3. SHAP on the classifier -- which features drove the attack-type call
     (falls back to model feature importances if shap is not installed)

Output is a plain-English sentence, which is what actually lands in a demo.
"""
from __future__ import annotations
import numpy as np
import pandas as pd

import config as C
from src.features import FEATURE_NAMES

try:
    import shap
    _HAS_SHAP = True
except Exception:
    _HAS_SHAP = False

HUMAN = {
    "geo_velocity_kmh": "implied travel speed between consecutive logins",
    "distance_from_home_km": "distance from this entity's usual location",
    "is_new_city": "login from a location never seen for this entity",
    "failed_auth_5min_entity": "failed authentications for this entity in 5 min",
    "failed_auth_5min_ip": "failed authentications from this IP in 5 min",
    "distinct_entities_per_ip_1h": "distinct accounts used from this IP in 1 hour",
    "ip_failure_rate_1h": "failure rate from this source IP",
    "is_new_resource": "first-ever access to this resource by this entity",
    "resource_novelty_ratio": "how rare this resource is org-wide",
    "peer_resource_deviation": "how rare this resource is among this entity's peer group",
    "new_resources_24h": "new resources touched in the last 24 hours",
    "resource_entropy_24h": "spread of resources accessed in 24 hours",
    "is_sensitive_resource": "resource is classified sensitive",
    "hour_zscore": "deviation from this entity's usual active hours",
    "is_off_hours_for_entity": "activity outside this entity's normal hours",
    "session_duration_zscore": "session length vs this entity's norm",
    "interevent_gap_zscore": "timing between events vs this entity's norm",
    "fingerprint_mismatch": "device fingerprint does not match history",
    "is_new_ip_for_entity": "source IP never seen for this entity",
    "auth_method_unusual": "authentication method unusual for this entity",
    "events_last_1h": "event volume in the last hour",
    "events_last_24h": "event volume in the last 24 hours",
    "offhours_count_7d": "off-hours accesses accumulated over 7 days",
    "sensitive_bytes_proxy_7d": "sensitive-resource activity over 7 days",
    "resource_breadth_7d": "breadth of resources touched over 7 days",
    "sensitive_offhours_7d": "off-hours accesses to sensitive resources over 7 days",
    "sensitive_ratio_7d": "share of recent activity on sensitive resources",
    "fingerprint_novelty": "how rarely this device fingerprint has been seen",
    "cmd_len": "command sequence length",
    "cmd_priv_count": "privileged commands in the session",
    "cmd_bigram_surprise": "unusual command ordering for this role",
    "entity_event_count": "history depth for this entity",
    "hour_sin": "time of day", "hour_cos": "time of day",
    "is_weekend": "weekend activity",
}


class Explainer:
    def __init__(self, classifier=None, background: pd.DataFrame | None = None):
        self.clf = classifier
        self.shap_explainer = None
        if _HAS_SHAP and classifier is not None:
            try:
                self.shap_explainer = shap.TreeExplainer(classifier.model)
            except Exception:
                self.shap_explainer = None

    # ------------------------------------------------------------------
    def classifier_attribution(self, X_row: pd.DataFrame, pred_class=None) -> dict:
        """
        Per-instance feature attribution for the classifier's decision,
        specific to `pred_class` -- the label actually shown to the analyst.

        BUG THIS FIXES: this used to average SHAP values across every class
        (or, without SHAP, return the model's single global
        feature_importances_ vector unchanged). Both give you "what usually
        matters to this model", not "why THIS event was called
        credential_stuffing" -- which is how an alert's headline label and
        its "why" text ended up describing two different attack patterns.
        """
        if self.clf is None or self.clf.model is None:
            return {}
        F = X_row[FEATURE_NAMES].to_numpy(dtype=float)
        classes = [str(c) for c in self.clf.model.classes_]
        cidx = classes.index(str(pred_class)) if pred_class is not None \
            and str(pred_class) in classes else None

        if self.shap_explainer is not None:
            try:
                vals = self.shap_explainer.shap_values(F)
                vec = self._select_class_shap(vals, cidx, len(FEATURE_NAMES))
                if vec is not None:
                    return dict(zip(FEATURE_NAMES, np.abs(vec)))
            except Exception:
                pass

        # No SHAP (or it failed). Rank by DIRECTIONAL ALIGNMENT with the
        # predicted class's signature:
        #   row_dev  -- how far THIS row sits from the flagged population
        #   sig      -- how far the PREDICTED CLASS sits from that same
        #               population, i.e. the direction a feature must move
        #               to be characteristic of this class
        # Only the aligned part counts (clipped at 0), so a feature moving
        # opposite to the class signature is never printed as support for
        # the label -- that is what produced "classified as device spoofing
        # because ... device fingerprint matches history".
        #
        # Global feature importance is deliberately NOT used as a
        # multiplier here. On a training pool this small the permutation
        # importance is degenerate -- correlated features mask each other,
        # so only a handful come back non-zero and everything else is
        # exactly 0.0, including fingerprint_mismatch and
        # fingerprint_novelty, which ARE the device-spoofing signature.
        # Multiplying by it silently deleted the real evidence. It is used
        # only as a gentle tie-breaker via (1 + imp).
        mean, std = self.clf.feat_mean_, self.clf.feat_std_
        sig = (self.clf.class_signature_ or {}).get(pred_class)
        if mean is None or sig is None:
            return self.clf.feature_importance()
        imp = self.clf.feature_importance() or {}
        row_dev = (F[0] - mean) / std
        aligned = np.clip(row_dev * sig, 0, None)
        return {f: float(aligned[i]) * (1.0 + float(imp.get(f, 0.0)))
                for i, f in enumerate(FEATURE_NAMES)}

    @staticmethod
    def _select_class_shap(vals, cidx, n_features):
        """Return the SHAP vector for ONE class, across SHAP's various
        multiclass output shapes. Averaging across classes (the old
        behaviour) answers 'why is this unusual', not 'why THIS class' --
        those are different questions, and only the second one belongs next
        to a specific predicted label."""
        if isinstance(vals, list):                # older SHAP: list of (n, feat)
            v = vals[cidx] if cidx is not None and cidx < len(vals) else vals[0]
            return np.asarray(v).reshape(-1, n_features)[0]
        arr = np.asarray(vals)
        if arr.ndim == 3:                         # newer SHAP: (n, feat, class)
            if cidx is not None and cidx < arr.shape[-1]:
                return arr[0, :, cidx]
            return arr[0].mean(axis=-1)
        return arr.reshape(-1, n_features)[0]     # binary / single-output

    # ------------------------------------------------------------------
    @staticmethod
    def _rank(contrib: dict, k=3):
        ranked = sorted(contrib.items(), key=lambda t: -abs(t[1]))
        return [(f, float(v)) for f, v in ranked[:k] if abs(v) > 1e-6]

    @staticmethod
    def top_factors(contrib: dict, seq_pf: np.ndarray | None = None, k=3):
        """ANOMALY evidence: why the risk score is high at all (baseline
        z-score deviation + sequence-autoencoder reconstruction error).
        Deliberately class-agnostic -- kept separate from
        `classifier_attribution`, which explains the attack-TYPE call."""
        merged = dict(contrib)
        if seq_pf is not None:
            for f, v in zip(FEATURE_NAMES, seq_pf):
                merged[f] = merged.get(f, 0.0) + 0.5 * float(v)
        return Explainer._rank(merged, k)

    PRETTY = {
        "brute_force": "brute-force authentication",
        "credential_stuffing": "credential stuffing",
        "impossible_travel": "impossible travel",
        "lateral_movement": "lateral movement",
        "device_spoofing": "device spoofing",
        "low_slow_exfil": "low-and-slow exfiltration",
        "benign_drift": "benign behavioural drift",
        "normal": "no clear attack pattern",
        "unclassified": "no attack-type model available",
    }

    # Concrete next step for the analyst reviewing this alert. Answers
    # "what do I do now" -- deliberately specific to the attack type rather
    # than a generic "investigate further", since that is the part of an
    # alert a SOC analyst actually acts on first.
    NEXT_STEPS = {
        "brute_force": "Lock or rate-limit the account/source IP, confirm "
            "with the entity whether the access attempts were theirs, and "
            "check whether any attempt after the burst succeeded.",
        "credential_stuffing": "Force a password reset for the affected "
            "account(s), check the source IP against known credential-"
            "stuffing infrastructure, and review other accounts touched "
            "from the same IP in the last hour.",
        "impossible_travel": "Contact the entity directly (out-of-band) to "
            "confirm the travel, and suspend the session if it cannot be "
            "confirmed within the incident window.",
        "lateral_movement": "Trace the resource-access sequence for this "
            "entity over the surrounding hours, identify the first "
            "resource that looks out of role, and check whether "
            "credentials for that entity are shared with other accounts.",
        "device_spoofing": "Verify the device fingerprint against asset "
            "inventory, revoke the session if the device is unrecognised, "
            "and re-enrol the legitimate device if this was a hardware or "
            "OS change.",
        "low_slow_exfil": "Pull a 7-day access history for this entity on "
            "sensitive resources, quantify total data touched, and check "
            "whether the off-hours pattern lines up with a known schedule "
            "(e.g. on-call, different timezone) before escalating.",
        "unclassified": "Review the anomaly evidence below manually -- no "
            "attack-type model is available to suggest a specific next "
            "step.",
        "normal": "No action required from the attack-type classifier; "
            "treat as a statistical outlier and check the anomaly evidence "
            "if the risk score is high.",
    }

    # Structural model inputs that are meaningless as analyst-facing
    # evidence. hour_sin/hour_cos are a cyclical encoding of the clock (an
    # analyst wants "outside this entity's normal hours", which
    # is_off_hours_for_entity already says); entity_event_count is how much
    # history the profiler has, not a property of the event. They can rank
    # highly on raw deviation, so they are excluded from the class-evidence
    # sentence rather than left to produce lines like "time of day: 0.95".
    NON_EVIDENCE = {"hour_sin", "hour_cos", "is_weekend", "entity_event_count"}

    # ------------------------------------------------------------------
    @staticmethod
    def _describe(factors: list, feat: dict, zscore: bool) -> list:
        """Turn (feature, value) pairs into analyst-readable phrases.
        `zscore=True` is for baseline/autoencoder evidence, where `v` really
        is a standard-deviation count. `zscore=False` is for classifier
        attribution, where `v` is a SHAP/importance weight, not a sigma --
        labelling it "deviation Xσ" would be a made-up statistic."""
        bits = []
        for f, v in factors:
            if not zscore and f in Explainer.NON_EVIDENCE:
                continue
            val = feat.get(f, 0.0)
            desc = HUMAN.get(f, f)
            count_like = f in ("failed_auth_5min_entity", "failed_auth_5min_ip",
                              "new_resources_24h", "offhours_count_7d",
                              "distinct_entities_per_ip_1h", "resource_breadth_7d",
                              "sensitive_offhours_7d", "events_last_1h", "events_last_24h")
            if f == "geo_velocity_kmh":
                bits.append(f"{desc} {val:,.0f} km/h")
            elif f == "distance_from_home_km":
                bits.append(f"{desc}: {val:,.0f} km")
            elif count_like:
                # A count of 0 is not evidence of anything.
                if not zscore and val == 0:
                    continue
                bits.append(f"{desc}: {val:,.0f}")
            elif val in (0.0, 1.0) and f.startswith(("is_", "fingerprint_", "auth_")):
                if val == 1.0:
                    bits.append(desc)
            elif zscore:
                bits.append(f"{desc} (deviation {v:.1f}\u03c3)")
            else:
                # Class evidence: a feature sitting at zero cannot be what
                # made this event look like the predicted attack type.
                if val == 0:
                    continue
                num = f"{val:,.0f}" if abs(val) >= 100 else f"{val:.2f}"
                bits.append(f"{desc}: {num}")
        return bits

    # ------------------------------------------------------------------
    @staticmethod
    def reason_text(event: dict, feat: dict, risk: float, pred: str,
                    factors: list, low_conf: bool = False,
                    class_factors: list | None = None, conf: float = 1.0,
                    runner_up: tuple | None = None,
                    cleared_threshold: bool = True) -> str:
        pretty = Explainer.PRETTY.get(pred, pred)
        anomaly_bits = Explainer._describe(factors, feat, zscore=True)

        # Headline. class_confidence (how sure the CLASSIFIER is about the
        # attack-type label) and low_conf (whether this ENTITY is a
        # cold-start case with thin history) are two independent signals --
        # conflating them is how a 31%-confidence guess ended up printed as
        # an unqualified "likely credential stuffing".
        if pred in (C.NORMAL, "unclassified"):
            head = f"Risk {risk:.1f} \u2014 anomalous, no specific attack type assigned."
        elif conf >= C.CLASS_CONF_HIGH:
            head = f"Risk {risk:.1f} \u2014 likely {pretty}."
        elif conf >= C.CLASS_CONF_LOW:
            head = f"Risk {risk:.1f} \u2014 probably {pretty} (classifier confidence {conf*100:.0f}%)."
        else:
            head = (f"Risk {risk:.1f} \u2014 anomalous; attack-type classifier's best "
                    f"guess is {pretty}, but confidence is low ({conf*100:.0f}%).")

        # ORDERING. The classification and the evidence FOR that
        # classification come first; general anomaly evidence comes second,
        # explicitly labelled as such.
        #
        # The previous order put the class-agnostic anomaly evidence
        # immediately after the headline. That evidence is dominated by
        # whichever raw feature deviated most -- almost always geo-velocity
        # or distance-from-home, because those produce enormous sigma
        # values. So a credential-stuffing alert opened with two sentences
        # of impossible-travel language, and an analyst reading top-down
        # saw the wrong attack described before ever reaching the evidence
        # that actually justified the label.
        signal = ""
        if pred not in (C.NORMAL, "unclassified"):
            class_bits = (Explainer._describe(class_factors, feat, zscore=False)[:3]
                          if class_factors else [])
            if class_bits:
                signal = (f" Classified as {pretty} because: "
                          + "; ".join(class_bits) + ".")
            else:
                # No feature in this event moves in the direction that
                # characterises the predicted class. Since "normal" is not a
                # selectable label, the classifier must still return its
                # closest match -- say that plainly instead of implying
                # evidence that does not exist.
                signal = (f" Closest attack type is {pretty}, but no feature in "
                          f"this event is characteristic of it \u2014 treat the "
                          f"type label as unsupported and judge on the anomaly "
                          f"evidence below.")

        alt = ""
        if runner_up and conf < C.CLASS_CONF_HIGH:
            alt_label, alt_conf = runner_up
            if alt_conf > 0.05:
                alt_pretty = Explainer.PRETTY.get(alt_label, alt_label)
                alt = f" Could also be {alt_pretty} ({alt_conf*100:.0f}%)."

        # General anomaly evidence, now clearly marked as a separate
        # question ("why is this unusual at all") so it cannot be misread
        # as the justification for the attack-type label above.
        why = ""
        if anomaly_bits:
            lead = (" Also unusual for this entity: " if signal
                    else " Flagged because: ")
            why = lead + "; ".join(anomaly_bits) + "."

        # Saying what is NORMAL is as useful to an analyst as what is not.
        calm = []
        if not feat.get("fingerprint_mismatch"):
            calm.append("device fingerprint matches history")
        if not feat.get("is_new_ip_for_entity"):
            calm.append("source IP is known for this entity")
        if not feat.get("is_sensitive_resource"):
            calm.append("resource is not classified sensitive")
        ctx = " Unchanged: " + ", ".join(calm[:2]) + "." if calm else ""
        cold = (" NOTE: entity has limited history \u2014 scored against its peer-group "
                "prior, treat confidence as low.") if low_conf else ""
        filler = ("" if cleared_threshold else
                 " NOTE: risk score did not clear the calibrated alert threshold "
                 "\u2014 included to fill the analyst budget, not a confirmed "
                 "high-risk incident; deprioritise versus threshold-clearing alerts.")
        return head + signal + alt + why + ctx + cold + filler

    # ------------------------------------------------------------------
    def _classifier_extras(self, X_row: pd.DataFrame, pred):
        """One classifier call -> (runner-up class+prob, full probability
        vector over every canonical attack type). Kept as a single call so
        build_alert doesn't invoke predict() three times over for one alert."""
        empty_probs = {a: 0.0 for a in C.ATTACK_TYPES}
        if self.clf is None or self.clf.model is None:
            return None, empty_probs
        try:
            _, _, proba, classes = self.clf.predict(X_row)
        except Exception:
            return None, empty_probs
        classes = list(classes)
        probs = dict(empty_probs)
        for c, p in zip(classes, proba[0]):
            if c in probs:
                probs[c] = round(float(p), 4)
        order = np.argsort(-proba[0])
        runner_up = None
        for idx in order:
            lbl = classes[idx]
            if lbl != pred:
                runner_up = (lbl, float(proba[0][idx]))
                break
        return runner_up, probs

    # ------------------------------------------------------------------
    def build_alert(self, event: dict, feat: dict, contrib: dict, risk: float,
                    pred: str, conf: float, seq_pf=None, low_conf=False,
                    cleared_threshold: bool = True) -> dict:
        factors = self.top_factors(contrib, seq_pf)

        class_factors, runner_up = [], None
        class_probs = {a: 0.0 for a in C.ATTACK_TYPES}
        if self.clf is not None and pred not in (C.NORMAL, "unclassified"):
            X_row = pd.DataFrame([{f: feat.get(f, 0.0) for f in FEATURE_NAMES}])
            attrib = self.classifier_attribution(X_row, pred)
            class_factors = self._rank(attrib, k=8)
            runner_up, class_probs = self._classifier_extras(X_row, pred)

        return {
            "alert_id": f"A{int(event['event_id']):08d}",
            "event_id": int(event["event_id"]),
            "entity_id": event["entity_id"],
            "entity_type": event.get("entity_type", ""),
            "timestamp": str(event["timestamp"]),
            "source_ip": event.get("source_ip", ""),
            "geo_location": event.get("geo_location", ""),
            "resource_accessed": event.get("resource_accessed", ""),
            "risk_score": round(float(risk), 1),
            "predicted_class": pred,
            "class_confidence": round(float(conf), 3),
            "class_probabilities": class_probs,
            "runner_up_class": runner_up[0] if runner_up else None,
            "runner_up_confidence": round(runner_up[1], 3) if runner_up else None,
            "low_confidence_entity": bool(low_conf),
            "low_confidence_classification": bool(pred not in (C.NORMAL, "unclassified")
                                                   and conf < C.CLASS_CONF_LOW),
            "cleared_threshold": bool(cleared_threshold),
            "top_factors": [{"feature": f, "contribution": round(v, 2),
                             "meaning": HUMAN.get(f, f)} for f, v in factors],
            "attack_signal_factors": [{"feature": f, "contribution": round(v, 4),
                                       "meaning": HUMAN.get(f, f)} for f, v in class_factors],
            "reason_text": self.reason_text(event, feat, risk, pred, factors, low_conf,
                                            class_factors, conf, runner_up,
                                            cleared_threshold),
            "recommended_action": self.NEXT_STEPS.get(
                pred, self.NEXT_STEPS["unclassified"]),
        }
