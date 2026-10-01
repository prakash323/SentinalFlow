# SentinelFlow — React SOC Console

Source: `frontend/src/` (`App.tsx`, `api/`, `auth/`, `layouts/`, `pages/`, `hooks/useTheme.tsx`, `utils/relatedActivity.ts`).

## 1. Frontend architecture

React 19 + TypeScript + Vite 8. Data fetching/caching via TanStack Query (`@tanstack/react-query`, 10s `staleTime`, no refetch-on-window-focus, retries only on `5xx`/network errors — never on a `4xx`, since a client error will not fix itself on retry). Routing via `react-router-dom` v7. Charts via Recharts. Forms via `react-hook-form` + `zod` resolvers. Animation via `motion`. Icons via `lucide-react`.

Route-level code splitting (`React.lazy`): the public marketing site (`PublicLayout`, `Home`) and every authenticated SOC page are separate chunks, so visiting one never pays the bundle cost of the other.

## 2. Routing

`App.tsx`'s route map (exact, as coded):

```
/            PublicLayout -> Home            (public)
/login       Login                            (redirects into the app if already signed in)
/dashboard   Dashboard                         \
/events                                         |
/events/new                                     |
/events/:eventId                                |
/predictions                                    |
/alerts                                         |
/alerts/:id                                      > all behind RequireAuth
/incidents                                      |
/incidents/:id                                   |
/entities                                       |
/entities/:entityId                             |
/simulator                                      |
/replay-runs            (AdminOnly)             |
/replay-runs/:runKey    (AdminOnly)             |
/audit-logs             (AdminOnly)             |
/system                                         |
*            NotFound (inside RequireAuth)     /
```

`RequireAuth` (`auth/RequireAuth.tsx`) guards everything under it; a signed-out visitor is redirected to `/login`. `AdminOnly` additionally gates the three admin-only screens **in the UI** — the API independently enforces the same restriction (`SecurityConfig`), so the UI guard is a UX convenience, not the actual security boundary.

## 3. Authentication (frontend side)

`auth/AuthContext.tsx`: HTTP Basic credentials are held only in the `api/client.ts` module's in-memory variable and validated by a real call to `GET /api/v1/auth/me` (never checked against a hard-coded value client-side). The session (`username`, `password`, and the `/auth/me` response) is cached in `sessionStorage` (not `localStorage`, so it does not outlive the browser tab) under the key `sentinelflow.session`, purely so a page reload does not force a re-login within the same tab. A `401` on an already-established session (rotated/revoked credentials) triggers an automatic logout back to `/login`.

## 4. API layer

`api/client.ts` — a single Axios instance (`baseURL` from `VITE_API_BASE_URL`, default `/` so the Vite dev proxy handles same-origin routing to `:8080`). A request interceptor attaches the Basic `Authorization` header from the in-memory credential; a response interceptor normalizes every error into one `ApiError` shape (`code`, `message`, `details`, `requestId`, `status`) whether it came from the backend's own `ErrorResponse` or from a network-level failure (no response at all, or a `502`/`503`/`504` from a gateway/proxy while the API is still starting).

`api/endpoints.ts` — one grouped export per resource (`authApi`, `dashboardApi`, `systemApi`, `eventsApi`, `predictionsApi`, `alertsApi`, `incidentsApi`, `entitiesApi`, `replayApi`, `auditApi`), each function mapping 1:1 to a specific backend endpoint (see `../api/api-reference.md` for the exact paths) — this file is the frontend's complete inventory of backend calls; nothing outside it talks to the API directly.

## 5. Pages

| Page | Route | What it shows |
|---|---|---|
| Dashboard | `/dashboard` | KPI totals, recent events/alerts, a time-bucketed trend chart, severity/status/type/source breakdowns, top-risk entities — all from `GET /dashboard/summary` |
| Events | `/events` | Filterable (entity/type/source), paged event list |
| Event detail | `/events/:eventId` | Canonical payload, processing trail (prediction + alert), and **Related activity** — client-side correlation via `utils/relatedActivity.ts` (see below) |
| Create event | `/events/new` | Manual event submission form (any signed-in analyst; the endpoint itself is public) |
| Predictions | `/predictions` | Every ML prediction with decision/score/attack-type/confidence/raw features |
| Alerts | `/alerts` | Filterable (status/severity/decision/entity/source) alert list, mixed ML/RULE |
| Alert detail | `/alerts/:id` | Explainability panel that correctly attributes the alert to either the ML model or the specific deterministic rule (`isRuleDetection = a.detectionType === 'RULE'`), ranked factors, a validated status-transition workflow, and an on-demand AI explanation |
| Incidents | `/incidents` | Filterable (status/entity/source) incident list with alert-count/max-severity/max-score/source rollups |
| Incident detail | `/incidents/:id` | Linked alerts, status-transition workflow, and three on-demand AI actions (explanation, evidence summary, investigation) |
| Entities | `/entities` | Searchable list of monitored entities with rollups |
| Entity detail | `/entities/:entityId` | Per-entity event/alert/incident rollups and latest-prediction snapshot |
| Simulator | `/simulator` | Six canned scenarios (see `system-architecture.md` §10) sent through the real pipeline from the browser, with live outcome polling against `GET /events/{id}/trail` |
| Replay runs *(admin)* | `/replay-runs`, `/replay-runs/:runKey` | Bulk reprocessing job creation/monitoring |
| Audit logs *(admin)* | `/audit-logs` | Full audit trail |
| System | `/system` | Live dependency probes, pipeline counts, alert-policy thresholds |

## 6. AI actions in the UI

Rendered via the shared `AiAssist` component (`components/AiAssist.tsx`), used on both Alert detail (one action: explanation) and Incident detail (three actions: explanation, evidence summary, investigation). Every request is read-only from the UI's own perspective — no AI response is ever written back into alert/incident state; a provider failure surfaces the same `503 AI_PROVIDER_UNAVAILABLE` the API returns, with the underlying alert/incident data remaining fully visible and usable.

## 7. Source-aware filtering & correlation

Every relevant list endpoint (`events`, `alerts`, `incidents`) supports a `source` filter, and incident rows show every distinct source among their linked alerts (`sources: string[]`) — genuine multi-source aggregation, since an incident's correlation key (`entityId:eventType`) does not itself depend on source.

`utils/relatedActivity.ts` implements exactly two pairwise correlation rules, computed client-side, at read time, over already-fetched events (never persisted, never asserting causality — see the module's own extensive doc comment and `../telemetry/physical-telemetry.md` §9 for the exact matching logic and its one known real-data limitation).

## 8. Theme support

`hooks/useTheme.tsx`: a `ThemeProvider` storing `'dark' | 'light'` in `localStorage` (`sentinelflow.theme`), defaulting to the OS `prefers-color-scheme` when nothing is stored, applied via a `data-theme` attribute on `<html>` (CSS reads this token) and reflected into the mobile browser-chrome `theme-color` meta tag. Both themes are real, implemented CSS states — not a cosmetic stub.

## 9. Command palette

`layouts/CommandPalette.tsx` (bound to `Ctrl/⌘+K` per the project's own README) — searches pages (using each `NavItem`'s `keywords`), entities, and accepts a pasted event ID for direct navigation, per `layouts/nav.ts`'s `ALL_NAV`/`navItemFor`.

## 10. What the frontend does not do

It never computes a score, decision, severity, or correlation-of-record itself for anything shown as platform data — the one exception, `relatedActivity.ts`, is explicitly a client-side, read-time, non-persisted convenience view, documented as such in its own module comment, not a second source of truth.
