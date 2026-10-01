/**
 * The one illustrative case every landing scene tells (so the page reads as a single story).
 * Illustrative only: these are not measured or live values, and every scene that shows them says so.
 * Model name/version are the strings the ML service really returns with each prediction.
 */
export const DEMO = {
  entity: 'USER-009',
  event: 'LOGIN',
  time: '10:42:04',
  incident: 'USER-009:LOGIN',
  /** inside the alert policy's critical band (>= 0.999) */
  score: 0.9994,
  factors: ['Rare device', 'Unusual location', 'Unseen IP'],
  model: { name: 'behavioral-anomaly-ensemble', version: 'pipeline-joblib' },
} as const;

export const ILLUSTRATIVE_NOTE = 'Illustrative example. Values are not measured or live data.';
