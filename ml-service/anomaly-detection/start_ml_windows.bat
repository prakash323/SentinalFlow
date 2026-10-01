@echo off
cd /d "%~dp0"
if not exist .venv (
    python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install -r requirements-api.txt
if not exist models\pipeline.joblib (
    echo Trained artifact missing. Running quick pipeline...
    python run_pipeline.py --quick
)
python api.py
