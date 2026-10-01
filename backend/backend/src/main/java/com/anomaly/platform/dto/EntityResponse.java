package com.anomaly.platform.dto;
import java.time.OffsetDateTime; import java.util.*;
public record EntityResponse(UUID id,String entityId,String entityType,String displayName,Map<String,Object> metadata,OffsetDateTime createdAt) {}
