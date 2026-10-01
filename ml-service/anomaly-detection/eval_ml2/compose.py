"""Compose the final ML-2 deliverables from a completed run (evaluation-only).

    python -m eval_ml2.compose A B          # metrics from run A, reproducibility comparison A vs B

Writes (new ML-2 namespace; never overwrites an existing report - it refuses if the target exists unless --force):
    reports/ml2_evaluation.md      the report
    reports/ml2_metrics.json       machine-readable metrics (run A) + run A/B comparison summary
    reports/ml2_split_manifest.json  machine-readable split manifest
"""
from __future__ import annotations

import json
import sys

from . import common as K
from . import findings as F
from . import report as R
from . import report_more as RM


def compose(run_a: str, run_b: str, force: bool = False):
    da = K.REPORTS / "ml2_runs" / run_a
    m = json.load(open(da / "metrics.json"))
    cmp = json.load(open(K.REPORTS / "ml2_runs" / f"compare_{run_a}_{run_b}.json"))
    targets = [K.REPORTS / "ml2_evaluation.md", K.REPORTS / "ml2_metrics.json", K.REPORTS / "ml2_split_manifest.json"]
    if not force:
        for t in targets:
            if t.exists():
                raise SystemExit(f"refusing to overwrite existing {t.name}; pass --force to replace ML-2's own output")
    head = f"""# ML-2 Reproducible Evaluation

*Scope: evaluation only. No production source, model artifact, threshold, database, Kafka topic or frontend file was changed; nothing was retrained or calibrated.
All numbers below are generated from `reports/ml2_metrics.json` by `eval_ml2/` (run `{run_a}`; run `{run_b}` reproduces it — see §12).*

"""
    parts = [head, R.sec_protocol(m), R.sec_manifest(m), RM.sec_leakage(m), RM.sec_batch_stream(m), RM.sec_scores(m), RM.sec_anomaly(m),
             RM.sec_classifier(m), RM.sec_attack(m), RM.sec_entity(m), RM.sec_parity(m), RM.sec_shortcuts(m), RM.sec_repro(m, cmp),
             F.sec_findings(m, cmp), F.sec_limitations(m), F.sec_baseline(m)]
    md = "\n\n".join(parts) + "\n"
    (K.REPORTS / "ml2_evaluation.md").write_text(md, encoding="utf-8")
    out = dict(m)
    out["run_comparison"] = {k: v for k, v in cmp.items() if k != "first_differences"}
    out["run_comparison"]["first_differences"] = cmp["first_differences"][:20]
    K.write_json(K.REPORTS / "ml2_metrics.json", out)
    K.write_json(K.REPORTS / "ml2_split_manifest.json", m["manifest"])
    print("wrote", [t.name for t in targets], f"({len(md):,} chars)")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    compose(args[0], args[1], force="--force" in sys.argv)
