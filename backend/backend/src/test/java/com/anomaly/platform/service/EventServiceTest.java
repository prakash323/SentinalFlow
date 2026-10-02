package com.anomaly.platform.service;

import com.anomaly.platform.dto.AlertResponse;
import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.dto.EventTrailResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.exception.PayloadTooLargeException;
import com.anomaly.platform.kafka.EventKafkaProducer;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EntityProfileRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.PredictionRepository;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*
 * Source-Aware SOC phase: EventService.list() switched from a hand-
 * branched if/else chain (entityId/eventType) to a Specification builder
 * so a third filter dimension (source) does not require an exponential
 * number of branches. Covers test list items 1 (event source filtering),
 * 4 (all-sources / no filter), 6 (pagination + source combined), 7
 * (existing entityId filtering unaffected), 12 (no N+1 - exactly one
 * repository call regardless of filter combination).
 *
 * "Unknown source value" (item 5) and full end-to-end filtering
 * correctness are proven against the real live database instead of via
 * mocks here - this project has no @DataJpaTest/embedded-database
 * infrastructure (checked pom.xml before writing this), and mocking
 * Spring Data's Specification composition beyond a single clause risks
 * testing Spring Data's internals rather than this phase's own logic.
 */
@ExtendWith(MockitoExtension.class)
class EventServiceTest {

    @Mock private EventRepository repo;
    @Mock private EntityProfileRepository entityRepository;
    @Mock private EventKafkaProducer kafkaProducer;
    @Mock private PredictionRepository predictionRepository;
    @Mock private AlertRepository alertRepository;
    @Mock private PredictionService predictionService;
    @Mock private AlertService alertService;

    private EventService eventService;

    @BeforeEach
    void setUp() {
        eventService = new EventService(
                repo, entityRepository, kafkaProducer, predictionRepository, alertRepository,
                predictionService, alertService
        );
    }

    @SuppressWarnings("unchecked")
    private Page<Event> stubEmptyPage() {
        Page<Event> page = Page.empty();
        when(repo.findAll(any(Specification.class), any(Pageable.class))).thenReturn(page);
        return page;
    }

    // ------------------------------------------------------------------
    // 4. All-sources behavior (no source filter) + 12. no N+1
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_withNoFilters_callsFindAllExactlyOnce() {
        stubEmptyPage();

        eventService.list(null, null, null, 0, 20);

        verify(repo, times(1)).findAll(any(Specification.class), any(Pageable.class));
    }

    // ------------------------------------------------------------------
    // 1. Event source filtering - Specification content, not just wiring
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_withSourceOnly_buildsEqualityPredicateOnSourceField() {
        stubEmptyPage();

        eventService.list(null, null, "physical-collector", 0, 20);

        ArgumentCaptor<Specification<Event>> captor = ArgumentCaptor.forClass(Specification.class);
        verify(repo).findAll(captor.capture(), any(Pageable.class));

        Root<Event> root = mock(Root.class);
        CriteriaQuery<?> query = mock(CriteriaQuery.class);
        CriteriaBuilder cb = mock(CriteriaBuilder.class);
        Path<Object> sourcePath = mock(Path.class);
        Predicate predicate = mock(Predicate.class);

        when(root.<Object>get("source")).thenReturn(sourcePath);
        when(cb.equal(sourcePath, "physical-collector")).thenReturn(predicate);

        Predicate result = captor.getValue().toPredicate(root, query, cb);

        verify(cb).equal(sourcePath, "physical-collector");
        assertThat(result).isEqualTo(predicate);
    }

    // ------------------------------------------------------------------
    // 7. Existing entityId filtering still works (unaffected by source)
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_withEntityIdOnly_buildsEqualityPredicateOnEntityEntityId() {
        stubEmptyPage();

        eventService.list("USER-001", null, null, 0, 20);

        ArgumentCaptor<Specification<Event>> captor = ArgumentCaptor.forClass(Specification.class);
        verify(repo).findAll(captor.capture(), any(Pageable.class));

        Root<Event> root = mock(Root.class);
        Path<Object> entityPath = mock(Path.class);
        Path<Object> entityIdPath = mock(Path.class);
        CriteriaQuery<?> query = mock(CriteriaQuery.class);
        CriteriaBuilder cb = mock(CriteriaBuilder.class);
        Predicate predicate = mock(Predicate.class);

        when(root.<Object>get("entity")).thenReturn(entityPath);
        when(entityPath.<Object>get("entityId")).thenReturn(entityIdPath);
        when(cb.equal(entityIdPath, "USER-001")).thenReturn(predicate);

        Predicate result = captor.getValue().toPredicate(root, query, cb);

        verify(cb).equal(entityIdPath, "USER-001");
        assertThat(result).isEqualTo(predicate);
    }

    // ------------------------------------------------------------------
    // 6. Pagination combined with source filtering
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_clampsPageSizeRegardlessOfSourceFilter() {
        stubEmptyPage();

        eventService.list(null, null, "python-simulator", 0, 500);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(repo).findAll(any(Specification.class), pageableCaptor.capture());

        assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(100);
    }

    // ------------------------------------------------------------------
    // Response shape unaffected when repo returns real data
    // ------------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    void list_returnsPageResponseWrappingRepositoryResult() {
        when(repo.findAll(any(Specification.class), any(Pageable.class))).thenReturn(Page.empty());

        PageResponse<?> result = eventService.list(null, null, null, 0, 20);

        assertThat(result.content()).isEmpty();
        assertThat(result.totalElements()).isZero();
    }

    // ---------------------------------------------------------------
    // create(): an event Kafka cannot carry is rejected before it is stored
    // ---------------------------------------------------------------

    @Test
    void create_rejectsAnUnpublishableEvent_beforePersistingIt() {

        EntityProfile entity = new EntityProfile();
        entity.setEntityId("HOST-1");
        when(entityRepository.findByEntityId("HOST-1")).thenReturn(Optional.of(entity));

        CreateEventRequest request = new CreateEventRequest(
                "EV-BIG", "HOST-1", "LOGIN", "v1", OffsetDateTime.now(), "test", Map.of("blob", "x"));
        doThrow(new PayloadTooLargeException("too large")).when(kafkaProducer).ensurePublishable(request);

        assertThatThrownBy(() -> eventService.create(request)).isInstanceOf(PayloadTooLargeException.class);

        verify(repo, never()).save(any());
        verify(kafkaProducer, never()).publish(any());
    }

    // ---------------------------------------------------------------
    // trail(): every alert for the event, not just the newest
    // ---------------------------------------------------------------

    @Test
    void trail_returnsEveryAlertForTheEvent_newestFirst_andKeepsAlertAsTheNewest() {

        Event event = new Event();
        event.setId(UUID.randomUUID());
        event.setEventId("EV-1");
        when(repo.findByEventId("EV-1")).thenReturn(Optional.of(event));
        when(predictionRepository.findTopByEvent_IdOrderByCreatedAtDesc(event.getId())).thenReturn(Optional.empty());

        Alert mlAlert = new Alert();
        mlAlert.setId(UUID.randomUUID());
        Alert ruleAlert = new Alert();
        ruleAlert.setId(UUID.randomUUID());
        when(alertRepository.findByEvent_IdOrderByCreatedAtDesc(event.getId())).thenReturn(List.of(mlAlert, ruleAlert));

        AlertResponse mlResponse = mock(AlertResponse.class);
        AlertResponse ruleResponse = mock(AlertResponse.class);
        when(alertService.get(mlAlert.getId())).thenReturn(mlResponse);
        when(alertService.get(ruleAlert.getId())).thenReturn(ruleResponse);

        EventTrailResponse trail = eventService.trail("EV-1");

        assertThat(trail.alerts()).containsExactly(mlResponse, ruleResponse);
        assertThat(trail.alert()).isSameAs(mlResponse);
    }

    @Test
    void trail_withNoAlerts_hasNullAlertAndEmptyList() {

        Event event = new Event();
        event.setId(UUID.randomUUID());
        event.setEventId("EV-2");
        when(repo.findByEventId("EV-2")).thenReturn(Optional.of(event));
        when(predictionRepository.findTopByEvent_IdOrderByCreatedAtDesc(event.getId())).thenReturn(Optional.empty());
        when(alertRepository.findByEvent_IdOrderByCreatedAtDesc(event.getId())).thenReturn(List.of());

        EventTrailResponse trail = eventService.trail("EV-2");

        assertThat(trail.alert()).isNull();
        assertThat(trail.alerts()).isEmpty();
    }
}
