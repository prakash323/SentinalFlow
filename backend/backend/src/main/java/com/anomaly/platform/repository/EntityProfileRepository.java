package com.anomaly.platform.repository;

import com.anomaly.platform.entity.EntityProfile;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;
import java.util.UUID;

public interface EntityProfileRepository
        extends JpaRepository<EntityProfile, UUID>, JpaSpecificationExecutor<EntityProfile> {

    Optional<EntityProfile> findByEntityId(String entityId);

    boolean existsByEntityId(String entityId);
}
