package com.anomaly.platform.repository;
import com.anomaly.platform.entity.AlertFactor; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface AlertFactorRepository extends JpaRepository<AlertFactor,UUID> { List<AlertFactor> findByAlert_IdOrderByRankAsc(UUID alertId); }
