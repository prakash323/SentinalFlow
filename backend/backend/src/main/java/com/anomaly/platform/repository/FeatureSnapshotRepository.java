package com.anomaly.platform.repository;
import com.anomaly.platform.entity.FeatureSnapshot; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface FeatureSnapshotRepository extends JpaRepository<FeatureSnapshot,UUID> { List<FeatureSnapshot> findTop20ByEntity_IdOrderByCreatedAtDesc(UUID entityId); }
