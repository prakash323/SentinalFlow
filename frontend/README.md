# SentinelFlow Console (frontend)

React 19 + TypeScript + Vite operations console for the SentinelFlow anomaly-detection platform. See the [root README](../README.md) for the full system and page overview.

## Develop

```bash
npm install
npm run dev        # http://localhost:5173 — proxies /api to http://127.0.0.1:8080
npm run typecheck  # tsc -b (strict), no bundle
npm run build      # strict type-check + production bundle in dist/
npm run preview    # serve the production bundle on :4173
```

The backend (and Postgres, Kafka, the ML service) must be running; see the root README.

## Structure

```
src/
  api/          axios client (Basic auth, error normalisation) + typed endpoint modules
  auth/         AuthContext — validates credentials against GET /api/v1/auth/me, keeps roles
  components/   ui.tsx (buttons, badges, states…), charts.tsx, feedback.tsx (toasts, drawer, modal)
  hooks/        useUrlState (filters live in the URL), useTheme, useDebounced, motion hooks (useReducedMotion, useSceneActive, useLoopStage)
  layouts/      AppShell (sidebar/topbar), CommandPalette (Ctrl/⌘+K), nav definition
  pages/        one file per route, lazy-loaded
  styles/       tokens.css (dark/light design tokens) → base → motion → components → layout → pages; public.css + story.css = landing page
  utils/        formatting, enum → colour tone mapping, alert/incident workflow rules
```

## Notes

- **Auth**: HTTP Basic against the Spring API. Credentials stay in memory + `sessionStorage` (cleared when the tab closes). Any 401 on an established session returns to the login screen.
- **Workflow rules** in `utils/workflow.ts` mirror `AlertService`/`IncidentService`; the backend stays authoritative (409 on an illegal move) and the UI only avoids offering moves that would be rejected.
- **Admin-only screens** (replay runs, audit logs) are guarded in the UI, and enforced by the API.
- **Deployed separately from the API?** Set `VITE_API_BASE_URL` at build time and add the frontend origin to the backend's `APP_CORS_ALLOWED_ORIGINS`.
- **Theme**: dark by default (follows the OS preference on first visit), toggle in the top bar.

## Landing page motion

The public home page (`/`) is a scroll-driven product story. Motion is a small shared system, not per-page code:

- `styles/motion.css` — easing/duration tokens (`--sf-ease`, micro 180 / ui 280 / reveal 600 / hero 900 ms) and the `.sf-*` utilities: `sf-reveal`, `sf-in` / `sf-stagger` (delay via `--i`), `sf-scale-in`, `sf-slide`, `sf-draw` (SVG paths), `sf-line`, `sf-crossfade`, `sf-product-transition`. Everything animates `transform` / `opacity` / `stroke-dashoffset` only.
- `components/public/Reveal.tsx` — the one-shot scroll trigger (adds `.is-in`); utilities key off it, so a scene needs no script of its own.
- `components/public/story/*` — one file per scene (hero stage, event stream, feature cards, anomaly chart, score ring, alert, investigation, metrics, console mockup). `story/demo.ts` holds the single illustrative case they all tell.
- Two scenes loop (hero stage, console mockup): they advance only while on screen, in a visible tab, and not paused, and have a real Pause button. Under `prefers-reduced-motion` nothing loops and every scene shows its finished state.
- Every number on the page is an illustrative example and says so; scores follow the product's real alert bands (`utils/tone.ts`).
