"""ML-2 stage runner (evaluation-only).

    python -m eval_ml2.run batch    --run-id A
    python -m eval_ml2.run stream   --run-id A --variant main|heldout|nodrift [--limit N]
    python -m eval_ml2.run parity   --run-id A
    python -m eval_ml2.run assemble --run-id A

Every stage writes only to reports/ml2_runs/<run-id>/ and records SHA-256 hashes of every production file (source, model
artifact, dataset) before and after, so the report can show that nothing production-side changed.
"""
from __future__ import annotations

import os
os.environ.setdefault("OMP_NUM_THREADS", "1")            # single-threaded numerics: removes thread-count nondeterminism
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

import argparse
import sys
import time

from . import common as K


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["batch", "stream", "parity", "assemble"])
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--variant", default="main", choices=["main", "heldout", "nodrift"])
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args(argv)

    out_dir = K.REPORTS / "ml2_runs" / a.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = a.stage + (f"_{a.variant}" if a.stage == "stream" else "")
    logf = open(out_dir / f"{tag}.log", "a", encoding="utf-8")

    def log(msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
        logf.flush()

    K.write_json(out_dir / f"hashes_before_{tag}.json", K.production_hashes())
    log(f"stage={a.stage} run={a.run_id} variant={a.variant} limit={a.limit}")
    from . import protocol as P
    p = P.build()
    t = time.time()
    if a.stage == "batch":
        from . import scoring as S
        S.batch_stage(p, out_dir, log=log)
    elif a.stage == "stream":
        from . import scoring as S
        S.stream_stage(p, a.variant, out_dir, log=log, limit=a.limit)
    elif a.stage == "parity":
        from . import parity as Y
        Y.parity_stage(p, out_dir, log=log)
    elif a.stage == "assemble":
        from . import assemble as Z
        Z.assemble(p, out_dir, log=log)
    K.write_json(out_dir / f"hashes_after_{tag}.json", K.production_hashes())
    log(f"stage {tag} finished in {time.time()-t:.0f}s")


if __name__ == "__main__":
    main()
