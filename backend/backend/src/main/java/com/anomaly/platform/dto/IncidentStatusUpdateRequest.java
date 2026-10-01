package com.anomaly.platform.dto;

import com.anomaly.platform.entity.IncidentStatus;
import jakarta.validation.constraints.NotNull;

public record IncidentStatusUpdateRequest(
        @NotNull
        IncidentStatus status
) {
}