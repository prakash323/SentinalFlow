"""ML-4: data + evaluation foundation. Isolated: nothing here is imported by, or modifies, the production scoring path.

Writes only under eval_ml4/data, reports/ml4*, and (if needed) models/candidates/ml4. The shipped models/pipeline.joblib and the ML-3
candidate are only ever READ. src/generate.py is not modified; eval_ml4/generator.py is an independent, profile-parameterised generator.
"""
