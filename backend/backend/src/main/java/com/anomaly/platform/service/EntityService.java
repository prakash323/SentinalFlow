package com.anomaly.platform.service;

import com.anomaly.platform.dto.CreateEntityRequest;
import com.anomaly.platform.dto.EntityDetailResponse;
import com.anomaly.platform.dto.EntityResponse;
import com.anomaly.platform.dto.EntitySummaryResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.entity.EntityProfile;
import com.anomaly.platform.entity.IncidentStatus;
import com.anomaly.platform.entity.Prediction;
import com.anomaly.platform.exception.DuplicateResourceException;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.EntityProfileRepository;
import com.anomaly.platform.repository.EventRepository;
import com.anomaly.platform.repository.IncidentRepository;
import com.anomaly.platform.repository.PredictionRepository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class EntityService {

    private final EntityProfileRepository repo;
    private final EventRepository eventRepository;
    private final AlertRepository alertRepository;
    private final PredictionRepository predictionRepository;
    private final IncidentRepository incidentRepository;

    public EntityService(
            EntityProfileRepository repo,
            EventRepository eventRepository,
            AlertRepository alertRepository,
            PredictionRepository predictionRepository,
            IncidentRepository incidentRepository
    ) {
        this.repo = repo;
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.predictionRepository = predictionRepository;
        this.incidentRepository = incidentRepository;
    }

    @Transactional
    public EntityResponse create(CreateEntityRequest r) {

        String entityId = r.entityId().trim();

        if (repo.existsByEntityId(entityId)) {
            throw new DuplicateResourceException("Entity already exists: " + entityId);
        }

        EntityProfile e = new EntityProfile();
        e.setEntityId(entityId);
        e.setEntityType(r.entityType().trim().toUpperCase());
        e.setDisplayName(r.displayName());
        e.setMetadata(r.metadata() == null ? Map.of() : r.metadata());

        return to(repo.save(e));
    }

    /*
     * Single-entity detail view: the same event/alert rollup the list
     * endpoint already computes (reusing the identical grouped queries,
     * scoped to this one entity's id, so the "peak alert score"
     * definition never drifts between the two endpoints) plus open
     * incident count and the most recent prediction ("current risk",
     * deliberately distinct from the peak alert score - see
     * EntityDetailResponse). Five total queries, none of them per-row:
     * find entity, event rollup, alert rollup, open incident count,
     * latest prediction.
     */
    @Transactional(readOnly = true)
    public EntityDetailResponse get(String id) {

        EntityProfile entity = repo.findByEntityId(id)
                .orElseThrow(() -> new NotFoundException("Entity not found: " + id));

        List<Object[]> eventRows = eventRepository.summarizeByEntity(List.of(entity.getId()));
        List<Object[]> alertRows = alertRepository.summarizeByEntity(List.of(entity.getId()));

        Object[] ev = eventRows.isEmpty() ? null : eventRows.get(0);
        Object[] al = alertRows.isEmpty() ? null : alertRows.get(0);

        long openIncidentCount = incidentRepository.countByEntity_EntityIdAndStatus(
                entity.getEntityId(),
                IncidentStatus.OPEN
        );

        Optional<Prediction> latestPrediction =
                predictionRepository.findTopByEntity_EntityIdOrderByCreatedAtDesc(entity.getEntityId());

        return new EntityDetailResponse(
                entity.getId(),
                entity.getEntityId(),
                entity.getEntityType(),
                entity.getDisplayName(),
                entity.getMetadata(),
                entity.getCreatedAt(),

                ev == null ? 0 : ((Number) ev[1]).longValue(),
                al == null ? 0 : ((Number) al[1]).longValue(),
                al == null || al[2] == null ? 0 : ((Number) al[2]).longValue(),
                al == null ? null : (BigDecimal) al[3],
                ev == null ? null : (OffsetDateTime) ev[2],

                openIncidentCount,

                latestPrediction.map(Prediction::getAnomalyScore).orElse(null),
                latestPrediction.map(Prediction::getDecision).orElse(null),
                latestPrediction.map(Prediction::getCreatedAt).orElse(null)
        );
    }

    /*
     * Paged entity list, optionally filtered by a case-insensitive
     * substring of entityId / displayName, with each entity's event and
     * alert rollup. The rollups are two grouped queries for the whole
     * page rather than one query per row.
     */
    @Transactional(readOnly = true)
    public PageResponse<EntitySummaryResponse> list(String q, int page, int size) {

        Pageable pageable = PageRequest.of(
                Math.max(page, 0),
                Math.min(Math.max(size, 1), 100),
                Sort.by(Sort.Direction.ASC, "entityId")
        );

        Specification<EntityProfile> spec = Specification.where(null);

        if (q != null && !q.isBlank()) {

            String like = "%" + q.trim().toLowerCase() + "%";

            spec = spec.and((root, query, cb) -> cb.or(
                    cb.like(cb.lower(root.<String>get("entityId")), like),
                    cb.like(cb.lower(cb.coalesce(root.<String>get("displayName"), "")), like)
            ));
        }

        Page<EntityProfile> entities = repo.findAll(spec, pageable);

        List<UUID> ids = entities.getContent().stream().map(EntityProfile::getId).toList();

        Map<UUID, Object[]> eventRollup = new HashMap<>();
        Map<UUID, Object[]> alertRollup = new HashMap<>();

        if (!ids.isEmpty()) {

            for (Object[] row : eventRepository.summarizeByEntity(ids)) {
                eventRollup.put((UUID) row[0], row);
            }

            for (Object[] row : alertRepository.summarizeByEntity(ids)) {
                alertRollup.put((UUID) row[0], row);
            }
        }

        return PageResponse.from(entities.map(e -> {

            Object[] ev = eventRollup.get(e.getId());
            Object[] al = alertRollup.get(e.getId());

            return new EntitySummaryResponse(
                    e.getId(),
                    e.getEntityId(),
                    e.getEntityType(),
                    e.getDisplayName(),
                    e.getCreatedAt(),
                    ev == null ? 0 : ((Number) ev[1]).longValue(),
                    al == null ? 0 : ((Number) al[1]).longValue(),
                    al == null || al[2] == null ? 0 : ((Number) al[2]).longValue(),
                    al == null ? null : (BigDecimal) al[3],
                    ev == null ? null : (OffsetDateTime) ev[2]
            );
        }));
    }

    private EntityResponse to(EntityProfile e) {

        return new EntityResponse(
                e.getId(),
                e.getEntityId(),
                e.getEntityType(),
                e.getDisplayName(),
                e.getMetadata(),
                e.getCreatedAt()
        );
    }
}
