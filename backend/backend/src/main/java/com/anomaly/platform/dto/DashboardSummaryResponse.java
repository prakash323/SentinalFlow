package com.anomaly.platform.dto;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

public record DashboardSummaryResponse(
        long totalEvents,
        long predictionCount,
        long alertCount,
        long openIncidentCount,
        List<EventResponse> recentEvents,
        List<AlertResponse> recentAlerts,
        List<TrendPointResponse> trend,
        Map<String, Long> alertsBySeverity,
        Map<String, Long> alertsByStatus,
        Map<String, Long> eventsByType,
        Map<String, Long> eventsByProcessingStatus,
        Map<String, Long> eventsBySource,
        List<EntityRiskResponse> topEntities,
        BigDecimal averageAnomalyScore,
        BigDecimal maxAnomalyScore,
        int trendHours
) {
}
