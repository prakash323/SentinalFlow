# ML-5 — Future collector contract for device-spoofing and low-and-slow exfiltration telemetry

**Status: specification only. Nothing in this document is implemented, and ML-5 fabricated no feature, no telemetry and no synthetic field to improve any metric.**
It records what the platform's collectors would have to supply before a *learnable* signal for these two attack types can exist. The current canonical event
cannot express either attack faithfully (ML-4, sections 8 and 13); ML-5 confirms that fixing serving parity and calibrating scores does not change that.

Evidence carried from ML-4 (canonical events, sealed data, ML-4 candidate, frozen baseline): low-and-slow exfiltration was detected in 10 of 24 sealed incidents (42 %);
device spoofing had exactly one usable signal — a first-event fingerprint mismatch flag — which fired on 6/6 P0 incidents and 0 benign events **because the generator keeps one
stable fingerprint string per entity**. That is a property of the synthetic data, not evidence about real devices. The "fingerprint concurrency" signal fired on 5 % of benign
events (precision 1.4 %) — dynamic IPs and VPN users make it noisy.

## 1. What the canonical event carries today

`event_id, entity_id, entity_type, timestamp, source_ip, geo_location, resource_accessed, auth_method, auth_success, session_duration, command_sequence, device_fingerprint`
(and the platform envelope: `eventType, eventVersion, occurredAt, source, payload`). There is **no** byte/volume field, **no** destination field, **no** connection counter,
and the device is a single opaque string. A slow exfiltration channel is invisible by construction: `resource_accessed`, `session_duration` and a command list cannot
represent "40 MB/day to a rarely-seen destination". A spoofed device that copies the fingerprint string is indistinguishable from the real one.

## 2. Device identity / spoofing — telemetry a collector would need to add

| Field (proposed name) | Meaning | Typical source | Type / cardinality | Missing-value policy | Spoofable? | Applies to |
|---|---|---|---|---|---|---|
| `device_attestation` | signed statement of hardware/boot integrity (TPM measured boot, secure element, MDM attestation), plus verification result | MDM / endpoint agent | enum `{verified, failed, absent}` + token id | `absent` (unknown) — **never** `verified` by default | hard | managed fleets, modern IoT |
| `client_cert_thumbprint`, `client_cert_issuer`, `client_cert_serial` | mTLS / 802.1X client certificate presented | gateway, RADIUS, proxy | string (hash) | `absent` marker | hard (key theft only) | service accounts, edge devices |
| `tls_client_fingerprint` (JA3/JA4) | fingerprint of the client TLS stack | proxy, IDS (Zeek) | string | `absent` marker | by mimicry | any TLS client |
| `network_attachment` | switch port / VLAN / AP / network segment / NAC posture | NAC, DHCP | structured | `absent` for VPN/remote — must not be read as "off-site = suspicious" | hard on-prem | wired / Wi-Fi, OT |
| `mac_address` (raw, separate from the fingerprint string) + `mac_randomised` flag | layer-2 identity and whether it is privacy-randomised | DHCP/NAC | string + bool | `absent` | trivial | fixed IoT only (modern clients randomise) |
| `os_stack_fingerprint` | TCP/IP stack characteristics vs the claimed OS | network sensor | string | `absent` | moderate | on-path sensors, unreliable behind NAT |
| `firmware_version`, `build_id`, `update_event` | reported build and whether a legitimate update just occurred | heartbeat | string + bool | `absent` | moderate | edge / OT devices |
| `device_id_stable` | a stable identifier issued by the platform at enrolment (not derived from mutable attributes) | enrolment service | string | required for enrolled devices | issuer-controlled | all enrolled devices |

Contract rules: every field is optional **but explicitly present** — a collector that cannot observe a field sends the documented `absent` marker; the serving layer must
never turn `absent` into `verified`/"matches". A change of a strong identity signal (attestation, certificate) within one entity is a first-class event, not a feature of the
fingerprint string. Legitimate re-enrolment / update events must be emitted so they can be told apart from spoofing.

## 3. Low-and-slow exfiltration — telemetry a collector would need to add

| Field (proposed name) | Meaning | Typical source | Notes |
|---|---|---|---|
| `bytes_out`, `bytes_in` (per event/session) | transfer volume | proxy, firewall, DLP, storage access logs | raw counts; never pre-aggregated by the collector (the feature layer aggregates) |
| `transfer_duration_ms` (or start/end) | lets the rate be derived: `bytes_out / duration` | same | needed for rate and burst-vs-trickle separation |
| `object_count`, `object_size_bytes` | number / size of objects read or written | storage / DB audit | separates "many small reads" from "one large read" |
| `dest_ip`, `dest_domain`, `dest_asn`, `dest_country`, `dest_category` | where the data went | proxy, DNS, NetFlow | destination first-seen / rarity is the core low-and-slow signal |
| `dest_first_seen_for_entity` (or enough history for the feature layer to derive it) | destination novelty per entity | derived | derive in the feature layer, not the collector |
| `connection_count`, `distinct_destinations`, `dns_query_count` (per window or per event) | connection frequency and fan-out | NetFlow, DNS logs | a trickle shows as many small, regular connections |
| `channel` | egress channel: HTTP upload, cloud sync, e-mail, removable media, DNS tunnel | DLP / proxy | separates policy-allowed sync from unusual channels |
| `session_id` | joins the events of one transfer session | gateway | lets slow transfers be reassembled |

Temporal aggregation is a **feature-layer** responsibility (rolling 1 h / 24 h / 7 d per-entity byte and destination statistics, causal, computed by the same
`StreamingFeatureExtractor` path that serving uses so training/serving parity is preserved). The collector's job is to supply raw per-event counters with a stable schema
version, UTC timestamps and the documented missing-value marker.

## 4. Rules any new field must satisfy (same principles as the ML-5 serving contract)

1. **Required, documented-unknown, or controlled error** — no silent default. A missing security-relevant value is never converted into a benign one.
2. **Schema-versioned** (`eventVersion`), timestamps UTC with offset, units explicit in the field name (`_bytes`, `_ms`).
3. **One code path**: the feature is computed by the shared extractor for both training and serving, and a parity regression test (identical canonical events → identical features
   within a documented tolerance) is added *before* the feature is used.
4. **No generator-authored ground truth** may leak into a field (e.g. an `is_spoofed` flag or an "expected fingerprint" taken from the simulator's profile file).

## 5. Acceptance criteria before any model work on these attack types

* Real or independently authored telemetry for at least the fields above, from ≥ 3 deployment profiles, with a *benign-concurrency / benign-large-transfer* measurement
  (backups, VPN, dynamic IPs, sanctioned bulk uploads) so false-alert cost can be estimated.
* ≥ 5 independent incidents per class in the training profiles and ≥ 3 in a held-out profile (the ML-4 coverage rule), with incident-grouped splits.
* The full sealed protocol (TRAIN → VALIDATION → FREEZE → TEST) and the reproducibility twin runs used in ML-3…ML-5.

## 6. Non-goals of ML-5

ML-5 did **not** add bytes, destinations, attestation, certificates or any other new field to the data, did not derive such features from existing columns and relabel them,
did not tune anything toward these two attack types, and does not claim any improvement on them.
