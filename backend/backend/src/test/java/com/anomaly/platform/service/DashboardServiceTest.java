package com.anomaly.platform.service;

import com.anomaly.platform.dto.DashboardSummaryResponse;
import com.anomaly.platform.dto.TrendPointResponse;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.IncidentRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * The dashboard's severity-filtered alert graph reads trend[].alertsBySeverity:
 * alerts per UTC hour of their createdAt, split by severity, zero-filled.
 */
@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    @Mock private EventRepository eventRepository;
    @Mock private AlertRepository alertRepository;
    @Mock private PredictionRepository predictionRepository;
    @Mock private IncidentRepository incidentRepository;
    @Mock private AlertFactorRepository alertFactorRepository;

    private DashboardService service;

    private static final DateTimeFormatter KEY = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH");

    @BeforeEach
    void setUp() {
        service = new DashboardService(
                eventRepository, alertRepository, predictionRepository, incidentRepository, alertFactorRepository);
        when(eventRepository.findAll(any(Pageable.class))).thenReturn(Page.empty());
        when(alertRepository.findAll(any(Pageable.class))).thenReturn(Page.empty());
    }

    private static String hourKey(int hoursAgo) {
        return OffsetDateTime.now(ZoneOffset.UTC).minusHours(hoursAgo).truncatedTo(ChronoUnit.HOURS).format(KEY);
    }

    @Test
    void trend_splitsAlertsPerHourBySeverity_zeroFilled_andConsistentWithTheTotal() {

        String now = hourKey(0);
        String twoHoursAgo = hourKey(2);
        when(alertRepository.hourlyCounts(any())).thenReturn(List.of(
                new Object[]{now, 5L},
                new Object[]{twoHoursAgo, 2L}));
        when(alertRepository.hourlyCountsBySeverity(any())).thenReturn(List.of(
                new Object[]{now, "CRITICAL", 3L},
                new Object[]{now, "MEDIUM", 2L},
                new Object[]{twoHoursAgo, "HIGH", 2L}));

        DashboardSummaryResponse summary = service.summary(8);

        List<TrendPointResponse> trend = summary.trend();
        assertThat(trend).hasSize(8);

        TrendPointResponse last = trend.get(7);
        assertThat(last.alerts()).isEqualTo(5L);
        assertThat(last.alertsBySeverity())
                .containsExactly(
                        java.util.Map.entry("CRITICAL", 3L),
                        java.util.Map.entry("HIGH", 0L),
                        java.util.Map.entry("MEDIUM", 2L),
                        java.util.Map.entry("LOW", 0L));

        assertThat(trend.get(5).alertsBySeverity()).containsEntry("HIGH", 2L);
        assertThat(trend.get(0).alertsBySeverity()).containsOnlyKeys("CRITICAL", "HIGH", "MEDIUM", "LOW")
                .allSatisfy((k, v) -> assertThat(v).isZero());

        for (TrendPointResponse point : trend) {
            long sum = point.alertsBySeverity().values().stream().mapToLong(Long::longValue).sum();
            assertThat(sum).isEqualTo(point.alerts());
        }

        verify(alertRepository).hourlyCountsBySeverity(any());
    }

    @Test
    void trend_coversEachSupportedWindow_withOneBucketPerHour() {

        assertThat(service.summary(24).trend()).hasSize(24);
        assertThat(service.summary(72).trend()).hasSize(72);
        assertThat(service.summary(500).trend()).hasSize(72); // capped
    }
}
