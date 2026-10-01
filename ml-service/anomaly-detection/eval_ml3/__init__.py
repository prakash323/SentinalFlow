"""ML-3: leakage-safe TRAINING pipeline for a FUTURE candidate model.

Nothing here touches production: api.py, src/, models/pipeline.joblib, the dataset, Spring Boot, Kafka, the frontend and the
database are never modified. The candidate is written to a NEW location (models/candidates/ml3/, and per-run copies under
reports/ml3_runs/). eval_ml2 is imported read-only (protocol, metrics, label vault, shortcut rules).
"""
