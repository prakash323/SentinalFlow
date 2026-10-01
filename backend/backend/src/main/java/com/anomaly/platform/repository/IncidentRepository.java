package com.anomaly.platform.repository;

import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.IncidentStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IncidentRepository
        extends JpaRepository<Incident, UUID>, JpaSpecificationExecutor<Incident> {

    Optional<Incident> findByIncidentKey(String key);

    Page<Incident> findByStatus(
            IncidentStatus status,
            Pageable pageable
    );

    Page<Incident> findByEntity_EntityId(
            String entityId,
            Pageable pageable
    );

    long countByStatus(IncidentStatus status);

    /*
     * Open incident count for one entity - same "open" definition
     * DashboardService already uses system-wide (IncidentStatus.OPEN,
     * not "not CLOSED"). Single indexed count via
     * idx_incidents_entity_status(entity_id, status).
     */
    long countByEntity_EntityIdAndStatus(
            String entityId,
            IncidentStatus status
    );

    /*
     * Newest active incident whose key is exactly `baseKey` or starts with
     * `baseKey + ":"` (the timestamp-suffixed keys used when an earlier
     * incident for the same entity/event type was already resolved or
     * closed). Prefix comparison uses substring equality, not LIKE, so
     * '%' or '_' inside an entity id are never treated as wildcards.
     */
    @Query("""
            SELECT i
            FROM Incident i
            WHERE i.status IN :statuses
              AND (i.incidentKey = :baseKey
                   OR SUBSTRING(i.incidentKey, 1, :prefixLength) = :prefix)
            ORDER BY i.createdAt DESC
            """)
    List<Incident> findActiveByKeyFamily(
            @Param("baseKey") String baseKey,
            @Param("prefix") String prefix,
            @Param("prefixLength") int prefixLength,
            @Param("statuses") Collection<IncidentStatus> statuses,
            Pageable pageable
    );
}
