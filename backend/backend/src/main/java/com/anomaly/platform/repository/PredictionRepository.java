package com.anomaly.platform.repository;

import com.anomaly.platform.entity.Prediction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PredictionRepository extends JpaRepository<Prediction, UUID>, JpaSpecificationExecutor<Prediction> {

    Optional<Prediction> findTopByEvent_IdOrderByCreatedAtDesc(
            UUID eventId
    );

    Optional<Prediction>
    findTopByEvent_IdAndModelNameAndModelVersionOrderByCreatedAtDesc(
            UUID eventId,
            String modelName,
            String modelVersion
    );

    /*
     * Most recent prediction for one entity, regardless of event or
     * model - used by EntityService for the entity detail view's
     * "current risk" (as opposed to EntitySummaryResponse.maxScore,
     * which is the entity's peak ALERT score). Single indexed lookup via
     * idx_predictions_entity_created(entity_id, created_at DESC).
     */
    Optional<Prediction> findTopByEntity_EntityIdOrderByCreatedAtDesc(
            String entityId
    );

    /*
     * One row: [averageAnomalyScore, maxAnomalyScore] (both null when
     * there are no predictions yet). Returned as a list so an aggregate
     * over an empty table does not need special Optional handling.
     */
    @Query("SELECT AVG(p.anomalyScore), MAX(p.anomalyScore) FROM Prediction p")
    List<Object[]> scoreStats();
}
