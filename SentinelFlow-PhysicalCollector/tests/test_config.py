"""
Configuration tests (PHASE S items 1-4): defaults, environment
overrides, CLI precedence, invalid values and bounds validation.

Every test passes an explicit argv so it never picks up pytest's own
command line, and monkeypatch.delenv/setenv keeps the real environment
out of the assertions.
"""
import pytest

import config
from config import Config, ConfigError, parse_args

_ALL_ENV = (
    "COLLECTOR_ENTITY_ID", "KAFKA_BOOTSTRAP_SERVERS", "KAFKA_TOPIC",
    "SESSION_POLL_INTERVAL", "SESSION_POLL_INTERVAL_SECONDS",
    "PROCESS_POLL_INTERVAL", "PROCESS_POLL_INTERVAL_SECONDS",
    "NETWORK_POLL_INTERVAL", "NETWORK_POLL_INTERVAL_SECONDS",
    "QUEUE_MAX_SIZE", "KAFKA_RETRY_BASE_DELAY", "KAFKA_RETRY_MAX_DELAY",
    "KAFKA_MAX_PENDING_EVENTS", "DEDUP_TTL_SECONDS", "DEDUP_MAX_ENTRIES",
    "CORRELATION_TTL_SECONDS", "CORRELATION_MAX_ENTRIES",
    "SHUTDOWN_TIMEOUT_SECONDS", "WORKER_RESTART_BASE_DELAY",
    "WORKER_RESTART_MAX_DELAY", "WORKER_HEALTHY_RESET_SECONDS",
    "HEARTBEAT_INTERVAL_SECONDS", "LOG_LEVEL", "LOG_FILE",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _ALL_ENV:
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------
# 1. Default configuration
# --------------------------------------------------------------------------

def test_defaults_match_the_platforms_existing_contract():
    cfg = parse_args([])

    # These three are the compatibility surface with the rest of
    # SentinelFlow and must not drift.
    assert cfg.topic == "raw.events.v1"
    assert cfg.kafka_bootstrap_servers == "localhost:9094"
    assert config.SOURCE == "physical-collector"
    assert config.EVENT_VERSION == "v1"


def test_defaults_for_every_continuous_operation_setting():
    cfg = parse_args([])

    assert cfg.poll_interval_seconds == 5.0
    assert cfg.process_poll_interval_seconds == 15.0
    assert cfg.network_poll_interval_seconds == 30.0
    assert cfg.queue_max_size == 5000
    assert cfg.kafka_retry_base_delay_seconds == 5.0
    assert cfg.kafka_retry_max_delay_seconds == 60.0
    assert cfg.dedup_ttl_seconds == 3600.0
    assert cfg.dedup_max_entries == 10000
    assert cfg.correlation_ttl_seconds == 300.0
    assert cfg.correlation_max_entries == 2000
    assert cfg.shutdown_timeout_seconds == 15.0
    assert cfg.worker_restart_base_delay_seconds == 1.0
    assert cfg.worker_restart_max_delay_seconds == 30.0
    assert cfg.heartbeat_interval_seconds == 60.0
    assert cfg.log_level == "INFO"


def test_default_entity_id_is_derived_from_the_hostname():
    cfg = parse_args([])
    assert cfg.entity_id.startswith("HOST-")
    assert cfg.entity_id == cfg.entity_id.strip()


# --------------------------------------------------------------------------
# 2. Environment overrides
# --------------------------------------------------------------------------

def test_every_documented_environment_variable_is_honored(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENTITY_ID", "HOST-FROM-ENV")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "broker:19092")
    monkeypatch.setenv("KAFKA_TOPIC", "raw.events.v9")
    monkeypatch.setenv("SESSION_POLL_INTERVAL", "7")
    monkeypatch.setenv("PROCESS_POLL_INTERVAL", "11")
    monkeypatch.setenv("NETWORK_POLL_INTERVAL", "13")
    monkeypatch.setenv("QUEUE_MAX_SIZE", "123")
    monkeypatch.setenv("KAFKA_RETRY_BASE_DELAY", "2")
    monkeypatch.setenv("KAFKA_RETRY_MAX_DELAY", "20")
    monkeypatch.setenv("DEDUP_TTL_SECONDS", "60")
    monkeypatch.setenv("DEDUP_MAX_ENTRIES", "77")
    monkeypatch.setenv("SHUTDOWN_TIMEOUT_SECONDS", "3")
    monkeypatch.setenv("WORKER_RESTART_BASE_DELAY", "0.5")
    monkeypatch.setenv("WORKER_RESTART_MAX_DELAY", "5")
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SECONDS", "9")
    monkeypatch.setenv("LOG_LEVEL", "warning")

    cfg = parse_args([])

    assert cfg.entity_id == "HOST-FROM-ENV"
    assert cfg.kafka_bootstrap_servers == "broker:19092"
    assert cfg.topic == "raw.events.v9"
    assert cfg.poll_interval_seconds == 7.0
    assert cfg.process_poll_interval_seconds == 11.0
    assert cfg.network_poll_interval_seconds == 13.0
    assert cfg.queue_max_size == 123
    assert cfg.kafka_retry_base_delay_seconds == 2.0
    assert cfg.kafka_retry_max_delay_seconds == 20.0
    assert cfg.dedup_ttl_seconds == 60.0
    assert cfg.dedup_max_entries == 77
    assert cfg.shutdown_timeout_seconds == 3.0
    assert cfg.worker_restart_base_delay_seconds == 0.5
    assert cfg.worker_restart_max_delay_seconds == 5.0
    assert cfg.heartbeat_interval_seconds == 9.0
    assert cfg.log_level == "WARNING"  # normalized, not rejected


def test_legacy_pre_2_0_interval_variable_names_still_work(monkeypatch):
    # These were the names the 1.x collector shipped with; someone may
    # already have them in a .bat/.env file.
    monkeypatch.setenv("PROCESS_POLL_INTERVAL_SECONDS", "21")
    monkeypatch.setenv("NETWORK_POLL_INTERVAL_SECONDS", "22")

    cfg = parse_args([])

    assert cfg.process_poll_interval_seconds == 21.0
    assert cfg.network_poll_interval_seconds == 22.0


def test_documented_name_wins_over_the_legacy_name(monkeypatch):
    monkeypatch.setenv("PROCESS_POLL_INTERVAL", "30")
    monkeypatch.setenv("PROCESS_POLL_INTERVAL_SECONDS", "99")

    assert parse_args([]).process_poll_interval_seconds == 30.0


def test_cli_flags_win_over_the_environment(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "from-env:9094")
    monkeypatch.setenv("QUEUE_MAX_SIZE", "10")

    cfg = parse_args([
        "--kafka-bootstrap-servers", "from-cli:9094", "--queue-max-size", "4242",
    ])

    assert cfg.kafka_bootstrap_servers == "from-cli:9094"
    assert cfg.queue_max_size == 4242


def test_empty_environment_value_falls_through_to_the_default(monkeypatch):
    monkeypatch.setenv("QUEUE_MAX_SIZE", "   ")
    assert parse_args([]).queue_max_size == 5000


def test_verbose_forces_debug_regardless_of_log_level(monkeypatch):
    import logging
    monkeypatch.setenv("LOG_LEVEL", "ERROR")

    assert parse_args([]).effective_log_level() == logging.ERROR
    assert parse_args(["--verbose"]).effective_log_level() == logging.DEBUG


# --------------------------------------------------------------------------
# 3. Invalid configuration fails early and clearly
# --------------------------------------------------------------------------

@pytest.mark.parametrize("variable,value", [
    ("QUEUE_MAX_SIZE", "not-a-number"),
    ("QUEUE_MAX_SIZE", "12.5"),            # a size must be an integer
    ("PROCESS_POLL_INTERVAL", "abc"),
    ("DEDUP_MAX_ENTRIES", "1e3"),
    ("HEARTBEAT_INTERVAL_SECONDS", ""),    # empty -> default, not an error
])
def test_unparseable_environment_values_raise_config_error(monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    if value == "":
        parse_args([])  # empty is treated as "unset", deliberately
        return
    with pytest.raises(ConfigError) as error:
        parse_args([])
    assert variable.lower().split("_")[0] in str(error.value).lower() or value in str(error.value)


def test_invalid_log_level_is_rejected(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "CHATTY")
    with pytest.raises(ConfigError, match="log_level"):
        parse_args([])


# --------------------------------------------------------------------------
# 4. Bounds validation
# --------------------------------------------------------------------------

def _valid() -> Config:
    return Config(entity_id="HOST-TEST")


@pytest.mark.parametrize("field,bad_value", [
    ("poll_interval_seconds", 0),
    ("poll_interval_seconds", -1),
    ("process_poll_interval_seconds", 0),
    ("network_poll_interval_seconds", -0.5),
    ("queue_max_size", 0),
    ("queue_max_size", -5),
    ("kafka_max_pending_events", 0),
    ("dedup_ttl_seconds", 0),
    ("dedup_max_entries", 0),
    ("correlation_ttl_seconds", 0),
    ("correlation_max_entries", 0),
    ("kafka_retry_base_delay_seconds", 0),
    ("worker_restart_base_delay_seconds", 0),
    ("heartbeat_interval_seconds", 0),
    ("shutdown_timeout_seconds", -1),
])
def test_out_of_range_values_are_rejected(field, bad_value):
    cfg = _valid()
    setattr(cfg, field, bad_value)
    with pytest.raises(ConfigError, match=field):
        cfg.validate()


@pytest.mark.parametrize("field", ["queue_max_size", "dedup_max_entries", "correlation_max_entries"])
def test_size_settings_must_be_integers_not_floats(field):
    cfg = _valid()
    setattr(cfg, field, 10.5)
    with pytest.raises(ConfigError, match=field):
        cfg.validate()


def test_shutdown_timeout_of_zero_is_allowed():
    cfg = _valid()
    cfg.shutdown_timeout_seconds = 0
    assert cfg.validate() is cfg  # "drain nothing" is a legitimate choice


def test_retry_max_below_base_is_rejected():
    cfg = _valid()
    cfg.kafka_retry_base_delay_seconds = 10.0
    cfg.kafka_retry_max_delay_seconds = 5.0
    with pytest.raises(ConfigError, match="kafka_retry_max_delay_seconds"):
        cfg.validate()


def test_restart_max_below_base_is_rejected():
    cfg = _valid()
    cfg.worker_restart_base_delay_seconds = 10.0
    cfg.worker_restart_max_delay_seconds = 1.0
    with pytest.raises(ConfigError, match="worker_restart_max_delay_seconds"):
        cfg.validate()


@pytest.mark.parametrize("field", ["entity_id", "kafka_bootstrap_servers", "topic"])
def test_blank_required_strings_are_rejected(field):
    cfg = _valid()
    setattr(cfg, field, "   ")
    with pytest.raises(ConfigError, match=field):
        cfg.validate()


def test_boolean_is_not_accepted_as_a_numeric_setting():
    # True == 1 in Python; a bool slipping into an interval would be a
    # silent misconfiguration rather than an error.
    cfg = _valid()
    cfg.poll_interval_seconds = True
    with pytest.raises(ConfigError, match="poll_interval_seconds"):
        cfg.validate()
