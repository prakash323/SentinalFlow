package com.anomaly.platform.dto;
import com.anomaly.platform.entity.AlertStatus; import jakarta.validation.constraints.NotNull;
public record StatusUpdateRequest(@NotNull AlertStatus status) {}
