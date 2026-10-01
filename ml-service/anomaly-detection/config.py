"""
Central configuration. Single source of truth for schema, paths and constants.
Nothing else in the project should hardcode a field name or a magic number.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
SAMPLE_DIR = DATA / "sample"
RAW_DIR = DATA / "raw"
FIGURES = ROOT / "figures"
MODELS = ROOT / "models"
REPORT = ROOT / "report"

for _d in (DATA, SAMPLE_DIR, RAW_DIR, FIGURES, MODELS, REPORT):
    _d.mkdir(parents=True, exist_ok=True)

RANDOM_SEED = 42

# ----------------------------------------------------------------------------
# Canonical event schema -- matches the problem statement table exactly.
# Every data source (synthetic, LANL, CERT) is adapted INTO this schema.
# ----------------------------------------------------------------------------
SCHEMA = [
    "event_id",
    "entity_id",          # user_id or device_id
    "entity_type",        # user / service_account / edge_device
    "timestamp",          # access or connection time
    "source_ip",          # origin of the access
    "geo_location",       # "city|lat|lon"
    "resource_accessed",  # file, endpoint, port, or device function
    "auth_method",        # password / token / certificate / biometric
    "auth_success",       # 0/1  (needed for brute force + credential stuffing)
    "session_duration",   # length of connection, seconds
    "command_sequence",   # ordered list of actions, "|"-joined
    "device_fingerprint", # OS/firmware version + MAC + protocol
]
LABEL_COLS = ["event_id", "label", "attack_id"]

ENTITY_TYPES = ["user", "service_account", "edge_device"]
ROLES = ["engineer", "finance", "hr", "admin", "ops"]
AUTH_METHODS = ["password", "token", "certificate", "biometric"]
COMMANDS = ["list", "read", "write", "exec", "sudo", "download", "delete"]

# ----------------------------------------------------------------------------
# Attack taxonomy. `benign_drift` is deliberately NOT an attack -- it exists to
# tune false positives, which is exactly what the problem statement asks for.
# ----------------------------------------------------------------------------
NORMAL = "normal"
ATTACK_TYPES = [
    "brute_force",
    "credential_stuffing",
    "impossible_travel",
    "lateral_movement",
    "device_spoofing",
    "low_slow_exfil",
]
EDGE_CASES = ["benign_drift"]
ALL_LABELS = [NORMAL] + ATTACK_TYPES + EDGE_CASES

# ----------------------------------------------------------------------------
# Generator sizing. Tune N_DAYS / N_ENTITIES down if your laptop is slow.
# ----------------------------------------------------------------------------
N_USERS = 140
N_SERVICE = 40
N_DEVICES = 20
N_DAYS = 30
TRAIN_DAYS = 20              # time-based split: days 1..20 train, 21..30 test
INJECTION_RATE = 0.015       # ~1.5% of sessions carry an injected pattern
CONFOUNDER_RATE = 0.06       # 6% of benign events are "weird but legitimate"

# ----------------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------------
ALERT_BUDGET = 0.01          # DEFAULT top 1% of events -- named in the eval
                              # criteria. Not a frozen constant: both
                              # run_pipeline.py and run_realtime.py accept
                              # --budget at runtime (see
                              # Detector.threshold_for_budget), and the
                              # dashboard exposes a live control over it.
# Shared budget levels swept for the multi-budget report tables
# (src/evaluate.py: budget_curve, incident_budget_curve) and offered as the
# dashboard's "current alert budget" choices -- one shared list so a chosen
# budget always has a matching precomputed row in both tables.
BUDGET_LEVELS = (0.005, 0.01, 0.015, 0.02, 0.03)
# Dashboard-only display default -- which of the levels above the sidebar's
# budget control opens on, on a fresh session. Deliberately separate from
# ALERT_BUDGET (the batch pipeline's own calibration budget, left at 1% to
# match the problem statement's stated example and keep every headline
# number in README.md/FIXES.md reproducible as documented): this only
# changes what the analyst sees FIRST, by re-reading the same precomputed
# budget_curve/incident_budget_curve row -- it never re-runs the pipeline
# or changes what "the" official queue is.
DASHBOARD_DEFAULT_BUDGET = 0.02
SEQ_LEN = 12                 # events per sequence window
SEQ_FIT_SAMPLE = 30000       # cap rows used to FIT the sequence model (memory)
SEQ_CHUNK = 20000            # scoring chunk size (memory)
COLD_START_K = 50            # shrinkage constant: w = n / (n + k)
COLD_START_MIN_EVENTS = 50   # below this, entity is flagged low_confidence
EWMA_ALPHA = 0.02            # baseline drift adaptation rate
DRIFT_PSI_THRESHOLD = 0.25   # PSI above this => concept drift notice
POISON_GUARD = True          # only low-risk events update the baseline

# Fusion weights. Weighted toward the baseline profiler because it is the
# only component that sees a spoofed device fingerprint as decisive: the
# isolation forest and the sequence autoencoder both score device spoofing
# around the 0.87 percentile (vs 0.99 for brute force), so an even blend
# averaged that attack type down below the alert threshold entirely.
# Measured on the bundled sample: PR-AUC 0.907 -> 0.912, device-spoofing
# incident recall 0.4 -> 0.6, total incidents caught 33/36 -> 34/36.
FUSION_WEIGHTS = {"baseline": 0.60, "iforest": 0.20, "sequence": 0.20}

# ----------------------------------------------------------------------------
# Attack-type classifier confidence bands, used to phrase alert explanations
# honestly instead of always saying "likely X" regardless of how sure the
# model actually is.
# ----------------------------------------------------------------------------
CLASS_CONF_HIGH = 0.65       # >= this: "likely X"
CLASS_CONF_LOW = 0.40        # <  this: "best guess is X, low confidence" + runner-up shown

# Classifier training-pool construction. A naive "every flagged event"
# pool is dominated by whichever attack type produces the most events per
# incident (brute force: 30-200 events/incident) and starves attack types
# that only ever produce a couple of anomalous events per incident
# (impossible travel, device spoofing) of any training examples at all --
# see src/evaluate.py:classifier_training_pool.
MAX_TRAIN_EVENTS_PER_INCIDENT = 6

# Hours either side of a candidate incident over which the entity's
# sustained risk level is aggregated when ranking the analyst queue.
# See src/evaluate.py:incident_scores.
INCIDENT_WINDOW_H = 8

# ----------------------------------------------------------------------------
# Geography. Real coordinates so geo-velocity is a physically meaningful number.
# ----------------------------------------------------------------------------
CITIES = {
    "Bengaluru":  (12.97, 77.59),
    "Hyderabad":  (17.39, 78.49),
    "Chennai":    (13.08, 80.27),
    "Pune":       (18.52, 73.86),
    "Mumbai":     (19.08, 72.88),
    "Delhi":      (28.61, 77.21),
    "Singapore":  (1.35, 103.82),
    "Frankfurt":  (50.11, 8.68),
    "London":     (51.51, -0.13),
    "Amsterdam":  (52.37, 4.90),
    "New York":   (40.71, -74.01),
    "Phoenix":    (33.45, -112.07),
    "Sao Paulo":  (-23.55, -46.63),
    "Lagos":      (6.52, 3.38),
    "Moscow":     (55.76, 37.62),
    "Shenzhen":   (22.54, 114.06),
}
HOME_CITIES = ["Bengaluru", "Hyderabad", "Chennai", "Pune", "Mumbai", "Delhi"]
FOREIGN_CITIES = [c for c in CITIES if c not in HOME_CITIES]

# ----------------------------------------------------------------------------
# Resources, per role. Zipf sampling over these creates habitual access sets.
# ----------------------------------------------------------------------------
RESOURCES = {
    "engineer": ["/repo/api", "/repo/core", "/ci/build", "/k8s/staging", "/logs/app",
                 "/db/dev", "/artifacts", "/k8s/prod", "/secrets/dev"],
    "finance":  ["/erp/ledger", "/erp/invoices", "/reports/q3", "/db/finance",
                 "/payroll/run", "/tax/filings", "/vendor/payments"],
    "hr":       ["/hris/profiles", "/hris/payroll", "/docs/policy", "/recruiting/ats",
                 "/reviews/2026", "/benefits"],
    "admin":    ["/ad/users", "/vpn/config", "/backup/nightly", "/siem/console",
                 "/certs/issue", "/firewall/rules", "/db/prod"],
    "ops":      ["/scada/hmi", "/plc/line1", "/plc/line2", "/historian/tags",
                 "/telemetry/edge", "/alarms/ack", "/maint/schedule"],
    "service_account": ["/api/v1/ingest", "/api/v1/sync", "/queue/consume",
                        "/db/replica", "/metrics/push", "/health"],
    "edge_device": ["sensor/temp", "sensor/pressure", "actuator/valve",
                    "heartbeat", "firmware/check", "telemetry/upload"],
}
SENSITIVE = {"/payroll/run", "/db/prod", "/secrets/dev", "/certs/issue",
             "/hris/payroll", "/ad/users", "/firewall/rules", "/tax/filings"}

OS_POOL = ["Windows 10.0.19045", "Windows 11.0.22631", "Ubuntu 22.04",
           "Ubuntu 24.04", "macOS 14.4", "RHEL 9.3", "Yocto 4.0", "FreeRTOS 10.5"]
PROTOCOLS = ["TLS1.3", "TLS1.2", "SSH2", "MQTT3.1.1", "OPC-UA", "HTTPS"]
