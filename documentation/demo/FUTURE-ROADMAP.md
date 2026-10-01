# SentinelFlow — Future Roadmap

This document separates what is **currently implemented and verified in source** from **future work only** — nothing below the line is built today.

## Currently implemented (for reference — see the other documentation files for detail)

- Canonical event ingestion from three sources (Python simulator, physical collector, in-console simulator), over two transports (REST, direct Kafka).
- Durable, idempotent event processing with retry + dead-letter handling.
- Two independent detection paths: an ML ensemble (`behavioral-anomaly-ensemble`) and two deterministic rules (`AUTH_BURST`, `NEW_PROCESS_EXTERNAL_CONNECTION`).
- Alert → incident correlation, with a validated status-transition lifecycle for both, synchronized between them.
- Optimistic locking on alert/incident mutations (`409 CONCURRENT_MODIFICATION`).
- Role-based security (`ADMIN`/`ANALYST`), BCrypt-hashed dev credentials, structured 401/403 responses.
- A read-only, evidence-grounded Spring AI layer (explanation, evidence summary, investigation) with explicit prompt-injection defenses, structurally incapable of mutating state.
- A React SOC console covering dashboard, events, predictions, alerts, incidents, entities, a live in-console simulator, replay runs, audit logs, and system status — with light/dark themes and a command palette.
- 190 backend automated tests, 97 physical-collector automated tests (including live Kafka integration), and a clean frontend typecheck/build, all re-verified from the current project root.

## Future work

### Telemetry
- **Additional Windows telemetry signals** beyond session/process/network — e.g. file-system access events, registry-change events, or Windows Defender/AV alert ingestion — none of which exist in the current collector.
- **Cross-platform collectors** (Linux/macOS equivalents of `SentinelFlow-PhysicalCollector`) — the current collector is Windows-specific (`psutil` calls that assume Windows session/account semantics).
- **Hardware-level entity disambiguation** for the physical collector (e.g. a MAC-address hash or `MachineGuid`) to resolve the documented hostname-collision limitation, only if a real multi-machine deployment ever needs it.

### Correlation
- **Stronger cross-event correlation**, potentially replacing the frontend's exact-match `relatedActivity.ts` rules with a backend-persisted correlation model, and/or resolving the documented LOGIN/PROCESS_START username-format mismatch with an explicit, agreed normalization rule (deliberately not invented in the current codebase without a real driving need).
- A `feature_snapshots` write path — the table and repository (`FeatureSnapshotRepository`) exist today but no service currently writes to it (see `../database/database-design.md` §3).
- Wiring `model_versions` into the actual prediction path (currently an unused registry table — see the same section) if multiple concurrently-active model versions ever need to be tracked.

### Collector reliability
- Automatic collector restart/supervision (e.g. as a Windows service) instead of a manually-launched foreground process.
- Back-pressure or local buffering if Kafka is unreachable for an extended period (today: `kafka-python`'s own `retries=5` is the only resilience; a sustained outage surfaces as a raised `KafkaError` in the collector process — see `VIVA_NOTES.md` §15).

### Observability
- Centralized log aggregation and a metrics dashboard beyond Actuator's raw `/actuator/metrics` (currently ADMIN-gated but not visualized).
- Structured tracing beyond the existing `X-Correlation-Id` propagation (e.g. OpenTelemetry spans across the REST → Kafka → ML hop).

### Production deployment
- Containerizing the ML service (this project's Dockerization work deliberately kept ML host-side due to a disk-space constraint during development — not a technical blocker, a resource one).
- A proper reverse proxy / load balancer with TLS termination in front of the API (not present in this codebase).
- CI/CD: running the existing 190+97 automated tests automatically on every change (currently run on demand only).
- Externalizing the two in-memory dev accounts to a real identity provider or secrets-managed credential store, if the deployment ever needs more than two fixed accounts.

### Security hardening
- Closing the public `POST /api/v1/events` gap with a shared producer credential or network-level restriction, since today's public access is an explicitly accepted (not fixed) residual risk — see `../security/security-design.md` §8.
- Rate limiting on the public event-ingestion endpoint.
- A secrets-manager integration (Vault, cloud KMS, etc.) instead of plain environment variables for `OPENROUTER_API_KEY` and the database/security credentials.

### Additional SOC capabilities
- Bulk/batch alert or incident status transitions from the UI (today: one at a time, per the existing endpoints).
- Saved filter presets / custom dashboards per analyst.
- Exporting an incident's full evidence + AI-generated narrative as a shareable report.

### ML
- Moving a candidate model (ML-3/ML-4/ML-5) to production only after a deliberate promotion decision — none of them are deployed today, and this document does not recommend a specific one without a fresh, current evaluation pass, which is explicitly out of scope for this documentation-only task.
- Live-traffic score-calibration re-tuning, flagged as an open item in the ML project's own `../../ml-service/anomaly-detection/ASSUMPTIONS.md`.
- Git LFS (or external artifact/release storage) for the large ML evaluation artifacts (`reports/`, `final_ml_package/`, `eval_ml4/`, `eval_ml5/`) before this repository's first Git commit — recommended, not yet configured.
