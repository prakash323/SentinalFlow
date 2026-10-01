"""ML-2 evaluation harness.

EVALUATION ONLY. Nothing in the production scoring path (api.py, src/*, run_*.py, models/) imports this package,
and this package never writes outside reports/. It imports the production classes read-only and drives them
exactly as deployed; it does not modify, subclass or monkey-patch anything in src/ (instrumentation wraps
methods on its own in-memory copy of the loaded artifact).
"""
