package com.anomaly.platform.kafka;

/*
 * Single source of truth for topic names.
 *
 * Previously the raw events topic name was duplicated as a private
 * constant in both EventKafkaProducer and EventKafkaConsumer, which
 * makes it easy for the two to silently drift apart.
 */
public final class KafkaTopics {

    public static final String RAW_EVENTS = "raw.events.v1";

    public static final String RAW_EVENTS_DLT = RAW_EVENTS + ".DLT";

    private KafkaTopics() {
    }
}
