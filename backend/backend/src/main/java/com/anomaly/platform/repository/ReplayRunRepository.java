package com.anomaly.platform.repository;
import com.anomaly.platform.entity.ReplayRun; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface ReplayRunRepository extends JpaRepository<ReplayRun,UUID> { Optional<ReplayRun> findByRunKey(String runKey); }
