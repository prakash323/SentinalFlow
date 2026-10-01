package com.anomaly.platform.repository;
import com.anomaly.platform.entity.ModelVersion; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface ModelVersionRepository extends JpaRepository<ModelVersion,UUID> { Optional<ModelVersion> findByModelNameAndVersion(String modelName,String version); }
