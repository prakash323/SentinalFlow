"""
Attack-type classification.

KEY DESIGN CHOICE (and the answer to the "extreme class imbalance" requirement):
the classifier is trained ONLY on the subset of events that the unsupervised
detector flagged -- not on all 300k events. Detection stays unsupervised, so it
can surface patterns it has never been labelled on; classification is supervised
and only ever sees a roughly balanced pool. This is also how a real SOC works:
the model does not need labels to raise an alert, only to name it.

LightGBM if installed; otherwise sklearn HistGradientBoostingClassifier.
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight

import config as C
from src.features import FEATURE_NAMES

try:
    import lightgbm as lgb
    _HAS_LGB = True
except Exception:
    _HAS_LGB = False


class AttackClassifier:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.backend = "lightgbm" if _HAS_LGB else "sklearn"
        self.model = None
        self.classes_ = None
        # Population stats over the flagged-and-training subset. Used so that
        # explanations can be instance-specific even when SHAP is not
        # installed -- a bare `feature_importances_` vector is identical for
        # every alert, which is what made every "why" section look the same
        # regardless of what actually triggered a given alert.
        self.feat_mean_ = None
        self.feat_std_ = None
        # Per-class feature signature: for each class, how that class's
        # training rows differ from the overall flagged population, in
        # standard deviations. This is what makes the no-SHAP fallback
        # genuinely CLASS-specific: global feature importance alone tells
        # you which features the model uses, but not which DIRECTION a
        # feature has to move to be evidence FOR a particular class. Without
        # it, a device-spoofing alert could cite "fingerprint" as its reason
        # while the row's fingerprint actually matched history -- evidence
        # pointing the opposite way, presented as support.
        self.class_signature_ = {}
        # Cached global importance. Populated in fit() so `feature_importance`
        # works even for backends -- HistGradientBoostingClassifier, the
        # no-lightgbm fallback -- that have no `feature_importances_`
        # attribute at all (it used to just return {} for these, which
        # silently deleted the classifier-attribution signal entirely).
        self._global_importance = None

    def fit(self, X_flagged: pd.DataFrame, y_flagged: np.ndarray,
            compute_importance: bool = True):
        F = X_flagged[FEATURE_NAMES].to_numpy(dtype=float)
        self.classes_ = sorted(set(y_flagged))
        self.feat_mean_ = np.nanmean(F, axis=0)
        self.feat_std_ = np.nanstd(F, axis=0) + 1e-9
        y_arr = np.asarray(y_flagged)
        self.class_signature_ = {
            c: (np.nanmean(F[y_arr == c], axis=0) - self.feat_mean_) / self.feat_std_
            for c in self.classes_
        }
        sw = compute_sample_weight("balanced", y_flagged)
        if self.verbose:
            print(f"[classify/{self.backend}] {len(F)} flagged events, "
                  f"{len(self.classes_)} classes")
        if self.backend == "lightgbm":
            self.model = lgb.LGBMClassifier(
                n_estimators=300, learning_rate=0.06, num_leaves=31,
                class_weight="balanced", random_state=C.RANDOM_SEED, verbose=-1)
            self.model.fit(F, y_flagged)
        else:
            from sklearn.ensemble import HistGradientBoostingClassifier
            self.model = HistGradientBoostingClassifier(
                max_iter=250, learning_rate=0.08, random_state=C.RANDOM_SEED)
            self.model.fit(F, y_flagged, sample_weight=sw)
        # compute_importance=False during cross_validate's per-fold refits,
        # where the importance vector is thrown away and would just be
        # recomputed 5x for nothing.
        if compute_importance:
            self._global_importance = self._compute_importance(F, y_flagged)
        return self

    def _compute_importance(self, F: np.ndarray, y: np.ndarray) -> dict:
        if hasattr(self.model, "feature_importances_"):
            return dict(zip(FEATURE_NAMES, self.model.feature_importances_))
        try:
            from sklearn.inspection import permutation_importance
            r = permutation_importance(self.model, F, y, n_repeats=5,
                                       random_state=C.RANDOM_SEED,
                                       scoring="f1_macro")
            return dict(zip(FEATURE_NAMES, np.clip(r.importances_mean, 0, None)))
        except Exception:
            return {}

    def predict(self, X: pd.DataFrame):
        F = X[FEATURE_NAMES].to_numpy(dtype=float)
        proba = self.model.predict_proba(F)
        classes = list(self.model.classes_)
        idx = proba.argmax(axis=1)
        return np.array([classes[i] for i in idx]), proba.max(axis=1), proba, classes

    def cross_validate(self, X_flagged, y_flagged, folds=5):
        F = X_flagged[FEATURE_NAMES].to_numpy(dtype=float)
        y = np.asarray(y_flagged)
        counts = pd.Series(y).value_counts()
        folds = int(min(folds, counts.min())) if counts.min() >= 2 else 0
        if folds < 2:
            return None
        skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=C.RANDOM_SEED)
        preds = np.empty(len(y), dtype=object)
        for tr, te in skf.split(F, y):
            m = AttackClassifier(verbose=False).fit(
                X_flagged.iloc[tr], y[tr], compute_importance=False)
            preds[te] = m.predict(X_flagged.iloc[te])[0]
        return {
            "report": classification_report(y, preds, zero_division=0, output_dict=True),
            "report_text": classification_report(y, preds, zero_division=0),
            "confusion": confusion_matrix(y, preds, labels=sorted(set(y))),
            "labels": sorted(set(y)),
            "y_true": y, "y_pred": preds,
        }

    def feature_importance(self):
        imp = self._global_importance
        if imp is None:
            if self.model is not None and hasattr(self.model, "feature_importances_"):
                imp = dict(zip(FEATURE_NAMES, self.model.feature_importances_))
            else:
                return {}
        return dict(sorted(imp.items(), key=lambda t: -t[1]))
