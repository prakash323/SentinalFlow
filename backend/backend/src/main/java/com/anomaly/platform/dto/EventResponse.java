package com.anomaly.platform.dto;

import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.EventProcessingStatus;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public record EventResponse(
        UUID id,
        String eventId,
        String entityId,
        String eventType,
        String eventVersion,
        OffsetDateTime occurredAt,
        String source,
        Map<String, Object> payload,
        EventProcessingStatus processingStatus,
        int processingAttempts,
        String lastProcessingError,
        OffsetDateTime processedAt,
        OffsetDateTime createdAt
) {

    /*
     * Single mapping used by every endpoint that returns an event, so the
     * list, detail and dashboard views can never disagree about fields.
     * The event's entity association is lazy; callers must map inside a
     * transaction.
     */
    public static EventResponse from(Event event) {

        return new EventResponse(
                event.getId(),
                event.getEventId(),
                event.getEntity().getEntityId(),
                event.getEventType(),
                event.getEventVersion(),
                event.getOccurredAt(),
                event.getSource(),
                event.getPayload(),
                event.getProcessingStatus(),
                event.getProcessingAttempts(),
                event.getLastProcessingError(),
                event.getProcessedAt(),
                event.getCreatedAt()
        );
    }
}
