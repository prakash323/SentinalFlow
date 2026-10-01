package com.anomaly.platform.dto;
import jakarta.validation.constraints.*; import java.util.Map;
public record CreateEntityRequest(@NotBlank String entityId,@NotBlank String entityType,String displayName,Map<String,Object> metadata) {}
