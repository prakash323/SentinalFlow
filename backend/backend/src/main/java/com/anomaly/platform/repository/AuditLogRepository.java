package com.anomaly.platform.repository;
import com.anomaly.platform.entity.AuditLog; import org.springframework.data.jpa.repository.JpaRepository; import java.util.*;
public interface AuditLogRepository extends JpaRepository<AuditLog,UUID> { }
