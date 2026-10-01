package com.anomaly.platform.service;

import com.anomaly.platform.dto.EntityDetailResponse;
import com.anomaly.platform.entity.DecisionState;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.entity.Prediction;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EntityProfileRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.IncidentRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Entity Intelligence phase: EntityService.get() is the single-entity
 * detail view backing GET /api/v1/entities/{entityId}. Covers the 12
 * scenarios from the approved test list; "existing simulator entity" and
 * "physical collector entity" are proven against the live database in
 * the phase's manual validation instead of duplicated here as unit
 * tests, since they are about real persisted data, not new logic.
 */
@ExtendWith(MockitoExtension.class)
class EntityServiceTest {

    @Mock
    private EntityProfileRepository repo;

    @Mock
    private EventRepository eventRepository;

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private PredictionRepository predictionRepository;

    @Mock
    private IncidentRepository incidentRepository;

    private EntityService entityService;

    private static final UUID ENTITY_UUID = UUID.randomUUID();
    private static final String ENTITY_ID = "USER-001";

    @BeforeEach
    void setUp() {
        entityService = new EntityService(
                repo, eventRepository, alertRepository, predictionRepository, incidentRepository
        );
    }

    private EntityProfile entityProfile() {
        EntityProfile e = new EntityProfile();
        e.setId(ENTITY_UUID);
        e.setEntityId(ENTITY_ID);
        e.setEntityType("USER");
        e.setDisplayName("Test User");
        e.setMetadata(Map.of());
        return e;
    }

    private void stubNoRollups() {
        when(repo.findByEntityId(ENTITY_ID)).thenReturn(Optional.of(entityProfile()));
        when(eventRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(alertRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(incidentRepository.countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN)).thenReturn(0L);
        when(predictionRepository.findTopByEntity_EntityIdOrderByCreatedAtDesc(ENTITY_ID)).thenReturn(Optional.empty());
    }

    // ------------------------------------------------------------------
    // 1. Entity with no events
    // ------------------------------------------------------------------
    @Test
    void entityWithNoEvents_returnsZeroCountsAndNullTimestamps() {
        stubNoRollups();

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.eventCount()).isZero();
        assertThat(result.lastEventAt()).isNull();
        assertThat(result.alertCount()).isZero();
        assertThat(result.maxScore()).isNull();
    }

    // ------------------------------------------------------------------
    // 2. Entity with normal events (no alerts)
    // ------------------------------------------------------------------
    @Test
    void entityWithNormalEvents_reportsEventCountWithZeroAlerts() {
        OffsetDateTime lastEventAt = OffsetDateTime.now();
        when(repo.findByEntityId(ENTITY_ID)).thenReturn(Optional.of(entityProfile()));
        when(eventRepository.summarizeByEntity(List.of(ENTITY_UUID)))
                .thenReturn(List.<Object[]>of(new Object[]{ENTITY_UUID, 42L, lastEventAt}));
        when(alertRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(incidentRepository.countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN)).thenReturn(0L);
        when(predictionRepository.findTopByEntity_EntityIdOrderByCreatedAtDesc(ENTITY_ID)).thenReturn(Optional.empty());

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.eventCount()).isEqualTo(42L);
        assertThat(result.lastEventAt()).isEqualTo(lastEventAt);
        assertThat(result.alertCount()).isZero();
    }

    // ------------------------------------------------------------------
    // 3 & 4. Entity with alerts / multiple alerts
    // ------------------------------------------------------------------
    @Test
    void entityWithMultipleAlerts_reportsAlertRollupAndPeakScore() {
        when(repo.findByEntityId(ENTITY_ID)).thenReturn(Optional.of(entityProfile()));
        when(eventRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(alertRepository.summarizeByEntity(List.of(ENTITY_UUID)))
                .thenReturn(List.<Object[]>of(new Object[]{ENTITY_UUID, 5L, 3L, new BigDecimal("0.98000")}));
        when(incidentRepository.countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN)).thenReturn(0L);
        when(predictionRepository.findTopByEntity_EntityIdOrderByCreatedAtDesc(ENTITY_ID)).thenReturn(Optional.empty());

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.alertCount()).isEqualTo(5L);
        assertThat(result.openAlertCount()).isEqualTo(3L);
        assertThat(result.maxScore()).isEqualByComparingTo("0.98000");
    }

    // ------------------------------------------------------------------
    // 5 & 6. Entity with an incident / multiple incidents (open count)
    // ------------------------------------------------------------------
    @Test
    void entityWithMultipleOpenIncidents_reportsOpenIncidentCount() {
        stubNoRollups();
        when(incidentRepository.countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN)).thenReturn(3L);

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.openIncidentCount()).isEqualTo(3L);
    }

    @Test
    void entityWithOnlyClosedIncidents_reportsZeroOpenIncidentCount() {
        // countByEntity_EntityIdAndStatus is scoped to OPEN specifically
        // (same "open" definition DashboardService already uses) - a
        // closed/resolved/investigating incident must not inflate this.
        stubNoRollups();

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.openIncidentCount()).isZero();
        verify(incidentRepository).countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN);
    }

    // ------------------------------------------------------------------
    // 7. Entity with no prediction
    // ------------------------------------------------------------------
    @Test
    void entityWithNoPrediction_latestPredictionFieldsAreNull() {
        stubNoRollups();

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.latestPredictionAnomalyScore()).isNull();
        assertThat(result.latestPredictionDecision()).isNull();
        assertThat(result.latestPredictionCreatedAt()).isNull();
    }

    // ------------------------------------------------------------------
    // 8. Entity with a latest prediction
    // ------------------------------------------------------------------
    @Test
    void entityWithLatestPrediction_populatesLatestPredictionFields() {
        OffsetDateTime predictedAt = OffsetDateTime.now();
        Prediction prediction = new Prediction();
        prediction.setAnomalyScore(new BigDecimal("0.68912"));
        prediction.setDecision(DecisionState.NORMAL);
        prediction.setCreatedAt(predictedAt);

        when(repo.findByEntityId(ENTITY_ID)).thenReturn(Optional.of(entityProfile()));
        when(eventRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(alertRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(incidentRepository.countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN)).thenReturn(0L);
        when(predictionRepository.findTopByEntity_EntityIdOrderByCreatedAtDesc(ENTITY_ID))
                .thenReturn(Optional.of(prediction));

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.latestPredictionAnomalyScore()).isEqualByComparingTo("0.68912");
        assertThat(result.latestPredictionDecision()).isEqualTo(DecisionState.NORMAL);
        assertThat(result.latestPredictionCreatedAt()).isEqualTo(predictedAt);
    }

    @Test
    void latestPrediction_isIndependentOfPeakAlertScore() {
        // The whole point of latestPrediction* existing separately from
        // maxScore: an entity's most recent activity can look NORMAL
        // even though it has a much higher historical peak alert score.
        // Neither field is derived from the other.
        Prediction prediction = new Prediction();
        prediction.setAnomalyScore(new BigDecimal("0.10000"));
        prediction.setDecision(DecisionState.NORMAL);
        prediction.setCreatedAt(OffsetDateTime.now());

        when(repo.findByEntityId(ENTITY_ID)).thenReturn(Optional.of(entityProfile()));
        when(eventRepository.summarizeByEntity(List.of(ENTITY_UUID))).thenReturn(List.of());
        when(alertRepository.summarizeByEntity(List.of(ENTITY_UUID)))
                .thenReturn(List.<Object[]>of(new Object[]{ENTITY_UUID, 5L, 0L, new BigDecimal("0.99000")}));
        when(incidentRepository.countByEntity_EntityIdAndStatus(ENTITY_ID, IncidentStatus.OPEN)).thenReturn(0L);
        when(predictionRepository.findTopByEntity_EntityIdOrderByCreatedAtDesc(ENTITY_ID))
                .thenReturn(Optional.of(prediction));

        EntityDetailResponse result = entityService.get(ENTITY_ID);

        assertThat(result.maxScore()).isEqualByComparingTo("0.99000");
        assertThat(result.latestPredictionAnomalyScore()).isEqualByComparingTo("0.10000");
        assertThat(result.latestPredictionDecision()).isEqualTo(DecisionState.NORMAL);
    }

    // ------------------------------------------------------------------
    // 9. Unknown entity
    // ------------------------------------------------------------------
    @Test
    void unknownEntity_throwsNotFoundAndNeverQueriesRollups() {
        when(repo.findByEntityId("NO-SUCH-ENTITY")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> entityService.get("NO-SUCH-ENTITY"))
                .isInstanceOf(NotFoundException.class);

        verify(eventRepository, never()).summarizeByEntity(any());
        verify(alertRepository, never()).summarizeByEntity(any());
        verify(incidentRepository, never()).countByEntity_EntityIdAndStatus(anyString(), any());
        verify(predictionRepository, never()).findTopByEntity_EntityIdOrderByCreatedAtDesc(anyString());
    }

    // ------------------------------------------------------------------
    // No N+1: exactly one call to each rollup/lookup method per get()
    // ------------------------------------------------------------------
    @Test
    void get_issuesExactlyOneCallToEachRollupQuery_noNPlusOne() {
        stubNoRollups();

        entityService.get(ENTITY_ID);

        verify(repo, times(1)).findByEntityId(ENTITY_ID);
        verify(eventRepository, times(1)).summarizeByEntity(List.of(ENTITY_UUID));
        verify(alertRepository, times(1)).summarizeByEntity(List.of(ENTITY_UUID));
        verify(incidentRepository, times(1)).countByEntity_EntityIdAndStatus(eq(ENTITY_ID), eq(IncidentStatus.OPEN));
        verify(predictionRepository, times(1)).findTopByEntity_EntityIdOrderByCreatedAtDesc(ENTITY_ID);
    }
}
