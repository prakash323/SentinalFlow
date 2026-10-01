package com.anomaly.platform.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

public record CreateReplayRunRequest(

        @NotBlank(message = "runKey is required")
        String runKey,

        String sourceName,

        @NotEmpty(
                message = "eventIds must contain at least one event ID"
        )
        List<
                @NotBlank(
                        message = "event ID must not be blank"
                )
                        String
                > eventIds

) {
}