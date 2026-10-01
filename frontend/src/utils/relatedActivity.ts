// Correlation Consumption v1 - EventDetail "Related activity".
//
// Pure, presentation-agnostic matching logic (no React/API coupling) so
// it can be reasoned about and exercised in isolation from the page
// that renders it. Implements EXACTLY the two approved pairwise rules,
// no more:
//
//   1. PROCESS_START <-> NETWORK_CONNECTION
//      exact match on payload.pid AND
//      NETWORK_CONNECTION.payload.processCreateTime == PROCESS_START.occurredAt
//      (string equality, no time tolerance)
//
//   2. LOGIN <-> PROCESS_START
//      same entityId (guaranteed by the caller - see EventDetail.tsx,
//      which only ever passes candidates already filtered to the
//      anchor's own entityId) AND same username (STRICT string
//      equality - see below) AND
//      PROCESS_START.occurredAt >= LOGIN.occurredAt AND
//      PROCESS_START.occurredAt < the next LOGIN/LOGOUT for that same
//      username, if one exists - else open-ended.
//
// This module computes a relationship at READ TIME only. It never
// persists anything, never changes any event/alert/incident, and never
// asserts causality - every result is "associated by <identifier>",
// nothing more.
//
// USERNAME FORMAT, VERIFIED AGAINST REAL STORED DATA (not assumed):
// LOGIN.payload.username is the bare OS username (from psutil.users(),
// e.g. "praka"). PROCESS_START.payload.username is the fully-qualified
// Windows account name (from psutil.Process.username(), e.g.
// "LAPTOP-HIK1MN09\\praka") - a real, different string for the exact
// same real person on this machine, confirmed live. This module does
// NOT normalize or strip the domain prefix - there is no existing,
// documented normalization rule in this project to justify inventing
// one here, so a strict string match is used exactly as specified. On
// this project's own real data, this means LOGIN<->PROCESS_START
// matches will not be found today - a known, reported limitation, not
// a bug in this logic.
import type { EventRecord } from '../types/domain';

export type RelatedActivityReason =
  | { kind: 'pid-process-create-time'; pid: number; processCreateTime: string }
  | { kind: 'username'; username: string };

export type RelatedActivityMatch = {
  event: EventRecord;
  reason: RelatedActivityReason;
};

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/**
 * PROCESS_START <-> NETWORK_CONNECTION: exact match, no tolerance.
 * Returns every candidate that satisfies the rule - never picks "the
 * best" one when several qualify (there is no meaningful ambiguity here
 * in practice, since pid+exact-timestamp is a precise key, but the
 * function still returns a list for consistency with the other rule and
 * to never silently drop a genuine duplicate).
 */
function findProcessNetworkMatches(anchor: EventRecord, candidates: EventRecord[]): RelatedActivityMatch[] {
  const matches: RelatedActivityMatch[] = [];

  if (anchor.eventType === 'PROCESS_START') {
    const anchorPid = asNumber(anchor.payload.pid);
    if (anchorPid === undefined) return matches;

    for (const candidate of candidates) {
      if (candidate.eventType !== 'NETWORK_CONNECTION') continue;
      const candidatePid = asNumber(candidate.payload.pid);
      const candidateCreateTime = asString(candidate.payload.processCreateTime);
      if (candidatePid === undefined || candidateCreateTime === undefined) continue;
      if (candidatePid === anchorPid && candidateCreateTime === anchor.occurredAt) {
        matches.push({
          event: candidate,
          reason: { kind: 'pid-process-create-time', pid: anchorPid, processCreateTime: candidateCreateTime },
        });
      }
    }
    return matches;
  }

  if (anchor.eventType === 'NETWORK_CONNECTION') {
    const anchorPid = asNumber(anchor.payload.pid);
    const anchorCreateTime = asString(anchor.payload.processCreateTime);
    if (anchorPid === undefined || anchorCreateTime === undefined) return matches;

    for (const candidate of candidates) {
      if (candidate.eventType !== 'PROCESS_START') continue;
      const candidatePid = asNumber(candidate.payload.pid);
      if (candidatePid === undefined) continue;
      if (candidatePid === anchorPid && candidate.occurredAt === anchorCreateTime) {
        matches.push({
          event: candidate,
          reason: { kind: 'pid-process-create-time', pid: anchorPid, processCreateTime: anchorCreateTime },
        });
      }
    }
  }

  return matches;
}

/**
 * The next LOGIN or LOGOUT event, for the same username, strictly after
 * `fromOccurredAt` - or undefined if none exists (open-ended window).
 * Candidates sharing the IDENTICAL occurredAt as `fromOccurredAt` (the
 * repeated-collector-restart-duplicate case) are correctly NOT treated
 * as a boundary, since they describe the same real instant, not a later
 * one.
 */
function nextSessionBoundary(username: string, fromOccurredAt: string, allSameUser: EventRecord[]): string | undefined {
  let earliest: string | undefined;
  for (const e of allSameUser) {
    if (e.eventType !== 'LOGIN' && e.eventType !== 'LOGOUT') continue;
    if (asString(e.payload.username) !== username) continue;
    if (e.occurredAt <= fromOccurredAt) continue;
    if (earliest === undefined || e.occurredAt < earliest) earliest = e.occurredAt;
  }
  return earliest;
}

/**
 * LOGIN <-> PROCESS_START. Returns EVERY LOGIN candidate that
 * legitimately bounds a given PROCESS_START (or every PROCESS_START a
 * given LOGIN legitimately bounds) - deliberately not narrowed to one,
 * so repeated LOGIN records from a collector restart surface as
 * multiple matching records rather than being silently collapsed into
 * a single assumed session.
 */
function findLoginProcessMatches(anchor: EventRecord, candidates: EventRecord[]): RelatedActivityMatch[] {
  const matches: RelatedActivityMatch[] = [];

  if (anchor.eventType === 'PROCESS_START') {
    const anchorUsername = asString(anchor.payload.username);
    if (anchorUsername === undefined) return matches;

    for (const candidate of candidates) {
      if (candidate.eventType !== 'LOGIN') continue;
      const candidateUsername = asString(candidate.payload.username);
      if (candidateUsername === undefined || candidateUsername !== anchorUsername) continue;
      if (anchor.occurredAt < candidate.occurredAt) continue;

      const upperBound = nextSessionBoundary(candidateUsername, candidate.occurredAt, candidates);
      if (upperBound !== undefined && anchor.occurredAt >= upperBound) continue;

      matches.push({ event: candidate, reason: { kind: 'username', username: candidateUsername } });
    }
    return matches;
  }

  if (anchor.eventType === 'LOGIN') {
    const anchorUsername = asString(anchor.payload.username);
    if (anchorUsername === undefined) return matches;

    const upperBound = nextSessionBoundary(anchorUsername, anchor.occurredAt, candidates);

    for (const candidate of candidates) {
      if (candidate.eventType !== 'PROCESS_START') continue;
      const candidateUsername = asString(candidate.payload.username);
      if (candidateUsername === undefined || candidateUsername !== anchorUsername) continue;
      if (candidate.occurredAt < anchor.occurredAt) continue;
      if (upperBound !== undefined && candidate.occurredAt >= upperBound) continue;

      matches.push({ event: candidate, reason: { kind: 'username', username: anchorUsername } });
    }
  }

  return matches;
}

/**
 * Entry point used by EventDetail.tsx. `candidates` must already be
 * scoped to the anchor event's own entityId (EventDetail fetches by
 * entityId before calling this) - this function does not filter by
 * entityId itself, and does not fetch anything.
 */
export function findRelatedActivity(anchor: EventRecord, candidates: EventRecord[]): RelatedActivityMatch[] {
  const pool = candidates.filter((c) => c.eventId !== anchor.eventId);

  return [
    ...findProcessNetworkMatches(anchor, pool),
    ...findLoginProcessMatches(anchor, pool),
  ];
}
