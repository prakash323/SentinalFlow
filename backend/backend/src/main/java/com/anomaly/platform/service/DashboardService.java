package com.anomaly.platform.service;

import com.anomaly.platform.dto.AlertResponse;
import com.anomaly.platform.dto.DashboardSummaryResponse;
import com.anomaly.platform.dto.EntityRiskResponse;
import com.anomaly.platform.dto.EventResponse;
import com.anomaly.platform.dto.TrendPointResponse;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.entity.Severity;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.IncidentRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/*
 * ================================================================
 * DASHBOARD SUMMARY
 * ================================================================
 *
 * Phase 3 addition: the React frontend's Dashboard page already existed
 * and calls GET /api/v1/dashboard/summary, but no backend endpoint backed
 * it. This assembles a read-only aggregate view from existing repositories
 * - it does not touch the Phase 1/2 event-processing pipeline.
 */
@Service
public class DashboardService {

    private static final int RECENT_LIMIT = 10;
    private static final int MAX_TREND_HOURS = 72;
    private static final List<Severity> SEVERITY_ORDER =
            List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW);
    private static final int TOP_ENTITIES = 5;

    private final EventRepository eventRepository;
    private final AlertRepository alertRepository;
    private final PredictionRepository predictionRepository;
    private final IncidentRepository incidentRepository;
    private final AlertFactorRepository alertFactorRepository;

    public DashboardService(
            EventRepository eventRepository,
            AlertRepository alertRepository,
            PredictionRepository predictionRepository,
            IncidentRepository incidentRepository,
            AlertFactorRepository alertFactorRepository
    ) {
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.predictionRepository = predictionRepository;
        this.incidentRepository = incidentRepository;
        this.alertFactorRepository = alertFactorRepository;
    }

    @Transactional(readOnly = true)
    public DashboardSummaryResponse summary(int requestedHours) {

        int hours = Math.min(Math.max(requestedHours, 1), MAX_TREND_HOURS);

        long totalEvents = eventRepository.count();
        long predictionCount = predictionRepository.count();
        long alertCount = alertRepository.count();
        long openIncidentCount = incidentRepository.countByStatus(IncidentStatus.OPEN);

        Pageable recentEventsPageable =
                PageRequest.of(0, RECENT_LIMIT, Sort.by(Sort.Direction.DESC, "occurredAt"));

        List<EventResponse> recentEvents =
                eventRepository.findAll(recentEventsPageable)
                        .map(EventResponse::from)
                        .getContent();

        Pageable recentAlertsPageable =
                PageRequest.of(0, RECENT_LIMIT, Sort.by(Sort.Direction.DESC, "createdAt"));

        List<AlertResponse> recentAlerts =
                alertRepository.findAll(recentAlertsPageable)
                        .map(this::toAlertResponse)
                        .getContent();

        List<TrendPointResponse> trend = buildTrend(hours);

        List<EntityRiskResponse> topEntities =
                alertRepository.topEntitiesByAlertCount(PageRequest.of(0, TOP_ENTITIES))
                        .stream()
                        .map(row -> new EntityRiskResponse(
                                (String) row[0],
                                ((Number) row[1]).longValue(),
                                (BigDecimal) row[2],
                                (OffsetDateTime) row[3]
                        ))
                        .toList();

        BigDecimal avgScore = null;
        BigDecimal maxScore = null;

        List<Object[]> scoreStats = predictionRepository.scoreStats();

        if (!scoreStats.isEmpty() && scoreStats.get(0)[0] != null) {

            Object[] row = scoreStats.get(0);

            avgScore = BigDecimal.valueOf(((Number) row[0]).doubleValue())
                    .setScale(5, java.math.RoundingMode.HALF_UP);

            maxScore = (BigDecimal) row[1];
        }

        return new DashboardSummaryResponse(
                totalEvents,
                predictionCount,
                alertCount,
                openIncidentCount,
                recentEvents,
                recentAlerts,
                trend,
                toCountMap(alertRepository.countGroupedBySeverity()),
                toCountMap(alertRepository.countGroupedByStatus()),
                toCountMap(eventRepository.countGroupedByType()),
                toCountMap(eventRepository.countGroupedByProcessingStatus()),
                toCountMap(eventRepository.countGroupedBySource()),
                topEntities,
                avgScore,
                maxScore,
                hours
        );
    }

    /*
     * [key, count] rows -> insertion-ordered map. Keys are enum values or
     * plain strings, so String.valueOf covers both.
     */
    private Map<String, Long> toCountMap(List<Object[]> rows) {

        Map<String, Long> result = new LinkedHashMap<>();

        for (Object[] row : rows) {
            result.put(String.valueOf(row[0]), ((Number) row[1]).longValue());
        }

        return result;
    }

    /*
     * ============================================================
     * HOURLY TREND (last 8 hours)
     * ============================================================
     *
     * IMPORTANT: OffsetDateTime.now() uses the JVM's default zone, but
     * event/alert timestamps are always stored and read back in UTC
     * (application.yml pins the JDBC connection's session TimeZone to
     * UTC). Comparing a JVM-local "now" against UTC-stored timestamps
     * would silently shift every bucket by the host's UTC offset, so
     * "now" is pinned to UTC explicitly here.
     */
    private List<TrendPointResponse> buildTrend(int hours) {

        OffsetDateTime nowUtc = OffsetDateTime.now(ZoneOffset.UTC);

        OffsetDateTime windowStart =
                nowUtc.minusHours(hours - 1L).truncatedTo(ChronoUnit.HOURS);

        /*
         * Hour buckets are counted by the database (GROUP BY on the UTC
         * hour) rather than by loading every event/alert in the window
         * into memory. Keys come back as 'YYYY-MM-DDTHH' text.
         */
        Map<String, Long> eventsPerHour = toCountMap(eventRepository.hourlyCounts(windowStart));
        Map<String, Long> alertsPerHour = toCountMap(alertRepository.hourlyCounts(windowStart));

        // hourKey -> (severity -> count), from one GROUP BY hour, severity query
        Map<String, Map<String, Long>> alertsPerHourBySeverity = new LinkedHashMap<>();
        for (Object[] row : alertRepository.hourlyCountsBySeverity(windowStart)) {
            alertsPerHourBySeverity
                    .computeIfAbsent(String.valueOf(row[0]), k -> new LinkedHashMap<>())
                    .put(String.valueOf(row[1]), ((Number) row[2]).longValue());
        }

        DateTimeFormatter keyFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH");
        DateTimeFormatter labelFormat =
                hours > 24
                        ? DateTimeFormatter.ofPattern("MM-dd HH:00")
                        : DateTimeFormatter.ofPattern("HH:00");

        List<TrendPointResponse> trend = new ArrayList<>();

        for (int i = hours - 1; i >= 0; i--) {

            OffsetDateTime bucketStart = nowUtc.minusHours(i).truncatedTo(ChronoUnit.HOURS);

            String key = bucketStart.format(keyFormat);

            Map<String, Long> hourSeverities = alertsPerHourBySeverity.getOrDefault(key, Map.of());
            Map<String, Long> bySeverity = new LinkedHashMap<>();
            for (Severity severity : SEVERITY_ORDER) {
                bySeverity.put(severity.name(), hourSeverities.getOrDefault(severity.name(), 0L));
            }

            trend.add(new TrendPointResponse(
                    bucketStart.format(labelFormat),
                    eventsPerHour.getOrDefault(key, 0L),
                    alertsPerHour.getOrDefault(key, 0L),
                    bucketStart,
                    bySeverity
            ));
        }

        return trend;
    }

    private AlertResponse toAlertResponse(Alert alert) {

        List<String> factors =
                alertFactorRepository.findByAlert_IdOrderByRankAsc(alert.getId())
                        .stream()
                        .map(AlertFactor::getFactor)
                        .toList();

        return new AlertResponse(
                alert.getId(),
                alert.getEntity() == null ? null : alert.getEntity().getEntityId(),
                alert.getEvent() == null ? null : alert.getEvent().getEventId(),
                alert.getEvent() == null ? null : alert.getEvent().getSource(),
                alert.getDecision(),
                alert.getSeverity(),
                alert.getStatus(),
                alert.getAnomalyScore(),
                alert.getConfidence(),
                alert.getFusedScore(),
                alert.getPolicyVersion(),
                factors,
                alert.getCreatedAt(),
                alert.getUpdatedAt(),
                alert.getIncident() == null
                        ? null
                        : alert.getIncident().getId(),
                alert.getRuleId(),
                alert.getRuleName(),
                alert.getRuleId() == null ? "ML" : "RULE"
        );
    }
}
