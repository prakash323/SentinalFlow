package com.anomaly.platform.entity;

/*
 * Tracks whether an already-persisted Event has been run through the
 * detection pipeline (feature extraction -> scoring -> prediction/alert/
 * incident) yet, and whether that attempt succeeded.
 *
 * This exists so that an accepted event's processing outcome is a durable,
 * queryable fact instead of only a log line.
 */
public enum EventProcessingStatus {
    PENDING,
    PROCESSED,
    FAILED
}
