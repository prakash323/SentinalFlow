"""Serving-parity regression tests (deterministic; no randomness, no network, no model loading except one optional full-scorer check).

Each parity test builds the platform payload of every canonical event of a fixed stream, maps it through the corrected boundary, extracts features with the
production StreamingFeatureExtractor and compares with extraction on the canonical events themselves (training extraction). The tolerance is
eval_ml5.parity_lib.TOLERANCE (bit-identical expected).

  python -m unittest eval_ml5.tests.test_contract_parity -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config as C                                                       # noqa: E402
from eval_ml4 import features4 as F4                                     # noqa: E402  (ML-4 datasets are read-only fixtures)
from eval_ml5 import parity_lib as PL                                    # noqa: E402
from eval_ml5 import platform_sim as PS                                  # noqa: E402
from eval_ml5.contract import (CONTRACT_VERSION, FIELD_POLICY, ContractError, ServingContract, ServingPipeline, UNSPECIFIED)   # noqa: E402
from src.features import FEATURE_NAMES, StreamingFeatureExtractor        # noqa: E402

TZ_SPEC = "Asia/Kolkata"
TZ = ZoneInfo(TZ_SPEC)
_CACHE: dict = {}


def dataset(did):
    if did not in _CACHE:
        ev = F4.load_events4(did)
        lab = pd.read_csv(F4.data_paths(did)["labels"]).set_index("event_id").loc[ev.event_id]
        _CACHE[did] = (ev, lab)
    return _CACHE[did]


def stream(did, entity_ids, cap=None):
    ev, _ = dataset(did)
    sub = ev[ev.entity_id.isin(entity_ids)].reset_index(drop=True)
    return PL.records_of(sub if cap is None else sub.iloc[:cap])


def first_entities(did, etype, n, max_events=1500, attacked=None):
    """Deterministic: the first n entities (sorted id) of a type whose total event count is bounded; optionally only (non-)attacked ones."""
    ev, lab = dataset(did)
    cnt = ev.groupby("entity_id").size()
    typ = ev.groupby("entity_id").entity_type.first()
    atk = set(ev.entity_id[lab.label.isin(C.ATTACK_TYPES).to_numpy()])
    cand = [e for e in sorted(cnt.index) if typ[e] == etype and cnt[e] <= max_events and (attacked is None or (e in atk) == attacked)]
    return cand[:n]


def attacked_by_type(did, attack, n=1, max_events=2500):
    ev, lab = dataset(did)
    cnt = ev.groupby("entity_id").size()
    ents = sorted(set(ev.entity_id[(lab.label == attack).to_numpy()]))
    return [e for e in ents if cnt[e] <= max_events][:n]


class Parity(unittest.TestCase):
    def assert_parity(self, recs, style="utc_z", include_type=True, tz_spec=TZ_SPEC, tz=TZ):
        A = PL.train_features(recs)
        reqs = [PS.to_platform_request(r, tz, style, include_type) for r in recs]
        B, _, errs = PL.serve_features(reqs, ServingContract(tz_spec, "user"))
        self.assertEqual(errs, [], "the corrected boundary rejected canonical events")
        c = PL.compare(A, B)
        self.assertTrue(c["within_tolerance"], f"features differ: {c['features_differing']} (max {c['max_abs_diff']})")
        return c

    # ------------------------------------------------------------------------------------------ event categories
    def test_normal_events(self):
        c = self.assert_parity(stream("P0-101", first_entities("P0-101", "user", 8, attacked=False)))
        self.assertTrue(c["bit_identical"])

    def test_attack_events_all_six_types(self):
        ents = []
        for a in C.ATTACK_TYPES:
            ents += attacked_by_type("P0-101", a, 1)
        recs = stream("P0-101", sorted(set(ents)))
        _, lab = dataset("P0-101")
        self.assertGreaterEqual(len({r["entity_id"] for r in recs}), 4)
        self.assertTrue(self.assert_parity(recs)["bit_identical"])

    def test_service_accounts(self):
        ents = first_entities("P3-401", "service_account", 2, max_events=700)
        self.assertEqual(len(ents), 2)
        self.assertTrue(self.assert_parity(stream("P3-401", ents, cap=1500))["bit_identical"])

    def test_edge_devices(self):
        ents = first_entities("P3-401", "edge_device", 2, max_events=700)
        self.assertEqual(len(ents), 2)
        self.assertTrue(self.assert_parity(stream("P3-401", ents, cap=1500))["bit_identical"])

    def test_command_heavy_events(self):
        ev, _ = dataset("P0-101")
        cnt = ev.groupby("entity_id").size()
        withcmd = ev[ev.command_sequence != ""].groupby("entity_id").size()
        ents = [e for e in sorted(withcmd.index) if cnt[e] <= 900][:5]
        recs = stream("P0-101", ents)
        multi = sum(1 for r in recs if str(r["command_sequence"]).count("|") >= 2)
        self.assertGreater(multi, 100, "fixture must contain many multi-token command sequences")
        self.assertTrue(self.assert_parity(recs)["bit_identical"])

    def test_private_and_public_ips(self):
        for did, expect_public in (("P0-101", False), ("P2-301", True)):
            recs = stream(did, first_entities(did, "user", 5, max_events=600))
            pub = np.mean([not (str(r["source_ip"]).startswith(("10.", "192.168.", "172.16."))) for r in recs])
            self.assertTrue(pub > 0.5 if expect_public else pub < 0.5, (did, pub))
            self.assertTrue(self.assert_parity(recs)["bit_identical"])

    def test_time_fields_every_timestamp_style_and_timezone(self):
        recs = stream("P0-101", first_entities("P0-101", "user", 4, max_events=400))
        for style in ("utc_z", "local_offset", "naive_local"):
            self.assertTrue(self.assert_parity(recs, style=style)["bit_identical"], style)
        # a deployment in another offset: the payload is generated in that offset and must map back to the same wall clock
        for spec in ("-08:00", "+05:30", "UTC"):
            from eval_ml5.contract import parse_timezone
            self.assertTrue(self.assert_parity(recs, style="utc_z", tz_spec=spec, tz=parse_timezone(spec))["bit_identical"], spec)
        # the SAME instant sent with different offsets is one canonical timestamp
        c = ServingContract(TZ_SPEC)
        a = c.canonicalize("e", "FILE_ACCESS", "2026-06-01T04:30:00Z", {"ip": "10.0.0.1", "location": "Pune|18.52|73.86", "resource": "/x"}).event["timestamp"]
        b = ServingContract(TZ_SPEC).canonicalize("e", "FILE_ACCESS", "2026-06-01T10:00:00+05:30", {"ip": "10.0.0.1", "location": "Pune|18.52|73.86", "resource": "/x"}).event["timestamp"]
        self.assertEqual(a, b)
        self.assertEqual(a, pd.Timestamp("2026-06-01 10:00:00"))

    def test_entity_type_not_sent_is_explicit_and_visible(self):
        """The platform sends no entityType today. For users the deployment default is right; for other entity types parity is NOT achievable without it
        (their events would join the wrong peer group in a mixed stream), and the boundary must SAY so (recorded assumption) instead of silently being wrong."""
        ents = (first_entities("P3-401", "user", 3, max_events=200) + first_entities("P3-401", "service_account", 2, max_events=500)
                + first_entities("P3-401", "edge_device", 2, max_events=500))
        recs = stream("P3-401", ents, cap=3000)
        reqs = [PS.to_platform_request(r, TZ, "utc_z", include_entity_type=False) for r in recs]
        r0 = ServingContract(TZ_SPEC, "user").canonicalize(reqs[0]["entityId"], reqs[0]["eventType"], reqs[0]["occurredAt"], reqs[0]["payload"], "x")
        self.assertTrue(any("entity_type=user" in a for a in r0.assumptions))
        B, _, _ = PL.serve_features(reqs, ServingContract(TZ_SPEC, "user"))
        c = PL.compare(PL.train_features(recs), B)
        self.assertFalse(c["within_tolerance"], "non-user entities cannot reach parity without entityType in a mixed stream")
        self.assertIn("peer_resource_deviation", c["features_differing"])
        # ...and with the type supplied they do
        self.assertTrue(self.assert_parity(recs)["bit_identical"])

    # ------------------------------------------------------------------------------------------ missing information
    def _base(self, **over):
        p = {"ip": "10.0.0.5", "location": "Pune|18.52|73.86", "resource": "/docs/a.pdf", "authMethod": "password", "loginSuccess": True,
             "deviceFingerprint": "Windows 11|3c:22:fb:10:9a:77|TLS1.3", "sessionDurationMinutes": 3.0}
        p.update(over)
        return {k: v for k, v in p.items() if v is not None}

    def test_missing_optional_fields_are_marked_never_defaulted_benignly(self):
        con = ServingContract(TZ_SPEC)
        p = self._base(authMethod=None, deviceFingerprint=None, sessionDurationMinutes=None)
        r = con.canonicalize("u1", "FILE_ACCESS", "2026-06-01T04:30:00Z", p, "e1")
        self.assertEqual(r.event["auth_method"], UNSPECIFIED)
        self.assertEqual(r.event["device_fingerprint"], UNSPECIFIED)
        self.assertEqual(sorted(r.degraded), ["auth_method", "device_fingerprint", "session_duration"])
        self.assertNotEqual(r.event["auth_method"], "password")        # the old boundary's benign look-alike default
        self.assertEqual(r.event["command_sequence"], "")              # absent commands = empty sequence (a valid canonical value)
        self.assertNotIn("command_sequence", r.degraded)

    def test_missing_fingerprint_is_not_carried_forward_and_is_fail_safe(self):
        con = ServingContract(TZ_SPEC)
        ex = StreamingFeatureExtractor()
        for i in range(12):                                            # a known device history
            ev = con.canonicalize("u1", "FILE_ACCESS", f"2026-06-01T04:{i:02d}:00Z", self._base(), f"e{i}").event
            ex.update_and_extract(ev)
        ev = con.canonicalize("u1", "FILE_ACCESS", "2026-06-01T04:30:00Z", self._base(deviceFingerprint=None), "e99")
        self.assertEqual(ev.event["device_fingerprint"], UNSPECIFIED)
        f = ex.update_and_extract(ev.event)
        self.assertEqual(f["fingerprint_mismatch"], 1.0, "withholding the fingerprint must look novel, not identical to the known device")

    def test_missing_auth_result(self):
        con = ServingContract(TZ_SPEC)
        ts = "2026-06-01T04:30:00Z"
        with self.assertRaises(ContractError) as cm:                   # a bare LOGIN without a result is NEVER read as success
            con.canonicalize("u1", "LOGIN", ts, self._base(loginSuccess=None), "e1")
        self.assertEqual(cm.exception.code, "MISSING_AUTH_RESULT")
        with self.assertRaises(ContractError):
            con.canonicalize("u1", "SOMETHING_NEW", ts, self._base(loginSuccess=None), "e2")
        self.assertEqual(con.canonicalize("u1", "LOGIN_FAILED", ts, self._base(loginSuccess=None), "e3").event["auth_success"], 0)
        self.assertEqual(con.canonicalize("u1", "LOGIN_SUCCESS", ts, self._base(loginSuccess=None), "e4").event["auth_success"], 1)
        r = con.canonicalize("u1", "FILE_ACCESS", ts, self._base(loginSuccess=None), "e5")
        self.assertEqual(r.event["auth_success"], 1)
        self.assertTrue(any("auth_success=1" in a for a in r.assumptions), "the post-authentication assumption must be recorded")
        with self.assertRaises(ContractError) as cm:
            con.canonicalize("u1", "LOGIN", ts, self._base(loginSuccess="maybe"), "e6")
        self.assertEqual(cm.exception.code, "INVALID_AUTH_RESULT")
        for txt, want in (("failed", 0), ("false", 0), ("success", 1), (False, 0), (0, 0), (1, 1)):
            self.assertEqual(con.canonicalize("u1", "LOGIN", ts, self._base(loginSuccess=txt), "e7").event["auth_success"], want, txt)

    def test_the_production_boundary_still_has_the_defects_this_suite_guards_against(self):
        """Control test: the suite must detect the old behaviour, otherwise a green result would prove nothing."""
        req = {"eventId": "e1", "entityId": "u1", "eventType": "LOGIN", "occurredAt": "2026-06-01T04:30:00Z", "source": "s",
               "payload": {"ip": "10.0.0.5", "location": "Pune|18.52|73.86", "sessionDurationMinutes": 2.5, "commandSequence": "sudo exec download"}}
        old = PS.legacy_canonical(req)
        self.assertEqual(old["auth_success"], 1, "legacy reads a missing LOGIN result as SUCCESS")
        self.assertEqual(old["session_duration"], 2.5, "legacy reads minutes as seconds")
        self.assertEqual(old["command_sequence"], "sudo exec download", "legacy leaves the separator as sent")
        self.assertEqual(old["timestamp"], pd.Timestamp("2026-06-01 04:30:00"), "legacy keeps UTC as if it were local")
        self.assertEqual(old["entity_type"], "user")
        recs = stream("P0-101", first_entities("P0-101", "user", 3, max_events=300))
        reqs = [PS.to_platform_request(r, TZ, "utc_z", True) for r in recs]
        B, _, _ = PL.serve_features(reqs, None, legacy=True)
        c = PL.compare(PL.train_features(recs), B)
        self.assertFalse(c["within_tolerance"])
        for f in ("hour_sin", "hour_cos", "hour_zscore"):
            self.assertIn(f, c["features_differing"])

    # ------------------------------------------------------------------------------------------ units, tokens, validation
    def test_units_and_tokenisation(self):
        con = ServingContract(TZ_SPEC)
        ts = "2026-06-01T04:30:00Z"
        self.assertEqual(con.canonicalize("u", "FILE_ACCESS", ts, self._base(sessionDurationMinutes=2.5), "1").event["session_duration"], 150.0)
        self.assertEqual(con.canonicalize("u", "FILE_ACCESS", ts, self._base(sessionDurationMinutes=None, sessionDurationSeconds=150), "2").event["session_duration"], 150.0)
        self.assertEqual(con.canonicalize("u", "FILE_ACCESS", ts, self._base(sessionDurationMinutes=None, session_duration=150), "3").event["session_duration"], 150.0)
        for bad in (-1, float("nan"), float("inf"), "abc", True):
            with self.assertRaises(ContractError, msg=repr(bad)):
                con.canonicalize("u", "FILE_ACCESS", ts, self._base(sessionDurationMinutes=bad), "4")
        with self.assertRaises(ContractError) as cm:
            con.canonicalize("u", "FILE_ACCESS", ts, self._base(sessionDurationSeconds=150), "5")
        self.assertEqual(cm.exception.code, "AMBIGUOUS_SESSION_DURATION")
        want = "sudo|exec|download"
        for v in ("sudo exec download", "SUDO, exec;download", "sudo|exec|download", ["sudo", "EXEC", "download"], "  sudo   exec\tdownload  "):
            self.assertEqual(con.canonicalize("u", "FILE_ACCESS", ts, self._base(commandSequence=v), "6").event["command_sequence"], want, v)
        with self.assertRaises(ContractError):
            con.canonicalize("u", "FILE_ACCESS", ts, self._base(commandSequence=42), "7")

    def test_required_fields_and_validation_errors(self):
        con = ServingContract(TZ_SPEC)
        ts = "2026-06-01T04:30:00Z"

        def err(code, etype="FILE_ACCESS", entity="u", occurred=ts, **over):
            with self.assertRaises(ContractError) as cm:
                con.canonicalize(entity, etype, occurred, self._base(**over), "x")
            self.assertEqual(cm.exception.code, code)
        err("MISSING_ENTITY_ID", entity=" ")
        err("MISSING_TIMESTAMP", occurred="")
        err("INVALID_TIMESTAMP", occurred="not-a-time")
        err("MISSING_SOURCE_IP", ip=None)
        err("INVALID_SOURCE_IP", ip="999.1.1.1")
        err("MISSING_LOCATION", location=None)
        err("MISSING_LOCATION", location="Unknown")
        err("INVALID_LOCATION", location="Pune")
        err("INVALID_LOCATION", location="Pune|95|10")
        err("INVALID_LOCATION", location="Pune|abc|10")
        err("MISSING_RESOURCE", resource=None)
        err("INVALID_ENTITY_TYPE", entityType="robot")
        self.assertEqual(con.canonicalize("u", "LOGIN", ts, self._base(resource=None), "y").event["resource_accessed"], "event:login")   # auth events: marker
        self.assertEqual(con.canonicalize("u", "FILE_ACCESS", ts, self._base(entityType="Service"), "z").event["entity_type"], "service_account")
        self.assertEqual(con.canonicalize("u", "FILE_ACCESS", ts, self._base(ip="2001:db8::1"), "i6").event["source_ip"], "2001:db8::1")
        with self.assertRaises(ValueError):
            ServingContract("")                                         # the deployment timezone is required: no silent default

    def test_out_of_order_is_flagged(self):
        con = ServingContract(TZ_SPEC)
        con.canonicalize("u", "FILE_ACCESS", "2026-06-01T04:30:00Z", self._base(), "a")
        r = con.canonicalize("u", "FILE_ACCESS", "2026-06-01T04:29:00Z", self._base(), "b")
        self.assertTrue(any(w.startswith("out_of_order") for w in r.warnings))

    # ------------------------------------------------------------------------------------------ contract completeness / idempotency
    def test_output_is_exactly_the_canonical_schema_and_every_field_has_a_policy(self):
        r = ServingContract(TZ_SPEC).canonicalize("u", "FILE_ACCESS", "2026-06-01T04:30:00Z", self._base(), "e")
        self.assertEqual(set(r.event), set(C.SCHEMA))
        self.assertEqual({p["canonical_field"] for p in FIELD_POLICY} | {"event_id"}, set(C.SCHEMA))
        self.assertEqual(CONTRACT_VERSION, "1.0")

    def test_duplicate_delivery_does_not_update_state_twice(self):
        class Scorer:
            calls = 0

            def process(self, event):
                Scorer.calls += 1
                return 12.5, None
        pipe = ServingPipeline(ServingContract(TZ_SPEC), Scorer())
        req = {"eventId": "dup-1", "entityId": "u", "eventType": "FILE_ACCESS", "occurredAt": "2026-06-01T04:30:00Z", "payload": self._base()}
        a, b = pipe.handle(req), pipe.handle(req)
        self.assertEqual(Scorer.calls, 1)
        self.assertFalse(a["duplicate"])
        self.assertTrue(b["duplicate"])
        self.assertEqual(a["riskScore"], b["riskScore"])

    def test_full_scorer_risk_scores_are_identical_through_the_corrected_boundary(self):
        """End to end with the real shipped scorer: platform payloads -> corrected boundary -> StreamingScorer must give the SAME risk as scoring the
        canonical events directly (both scorers start from an identical fresh copy of the artifact)."""
        import joblib
        from src.explain import Explainer
        from src.realtime import StreamingScorer
        path = ROOT / "models" / "pipeline.joblib"
        if not path.exists():
            self.skipTest("models/pipeline.joblib not present")
        recs = stream("P0-101", first_entities("P0-101", "user", 2, max_events=120))[:120]

        def scorer():
            art = joblib.load(path)
            return StreamingScorer(art["profiler"], art["detector"], art.get("classifier"), Explainer(art.get("classifier")), threshold=art.get("threshold"))
        direct = [scorer_risk for scorer_risk in (lambda s: [s.process(r)[0] for r in recs])(scorer())]
        pipe = ServingPipeline(ServingContract(TZ_SPEC), scorer())
        served = [pipe.handle(PS.to_platform_request(r, TZ, "utc_z", True))["riskScore"] for r in recs]
        self.assertEqual(len(direct), len(served))
        self.assertTrue(np.allclose(np.round(direct, 3), served, rtol=0, atol=1e-9), "risk scores differ through the corrected boundary")

    def test_determinism_two_passes_are_bit_identical(self):
        recs = stream("P0-101", first_entities("P0-101", "user", 4, max_events=400))
        reqs = [PS.to_platform_request(r, TZ, "utc_z", True) for r in recs]
        a, _, _ = PL.serve_features(reqs, ServingContract(TZ_SPEC))
        b, _, _ = PL.serve_features(reqs, ServingContract(TZ_SPEC))
        self.assertTrue(np.array_equal(a, b))


if __name__ == "__main__":
    unittest.main(verbosity=2)
