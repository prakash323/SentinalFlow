package com.anomaly.platform.repository;
import com.anomaly.platform.entity.AlertFactor; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface AlertFactorRepository extends JpaRepository<AlertFactor,UUID> {
    List<AlertFactor> findByAlert_IdOrderByRankAsc(UUID alertId);

    /*
     * Detection Engine 2.0: the next free rank when appending an escalation's
     * evidence to an alert that already has factors. alert_factors has
     * UNIQUE(alert_id, rank) (V8), so the rank cannot simply restart at 1.
     */
    long countByAlert_Id(UUID alertId);
}
