package com.anomaly.platform.ai;

import java.util.Locale;

/*
 * How much the analyst-assistance layer is asked to write.
 *
 * CONCISE is the default everywhere: a few short lines that lead with the
 * strongest evidence. DETAILED is strictly opt-in (the "Show detailed
 * analysis" interaction) and only changes the length/format instruction
 * appended to the prompt - the evidence, the grounding rules and the
 * read-only guarantees are identical in both modes.
 */
public enum AiDetail {

    CONCISE,
    DETAILED;

    /*
     * Parses the optional `detail` query parameter. Absent/blank means
     * CONCISE. Anything else that is not one of the two known values is a
     * client error (mapped to 400 by GlobalExceptionHandler), not a silent
     * fallback.
     */
    public static AiDetail parse(String raw) {

        if (raw == null || raw.isBlank()) {
            return CONCISE;
        }

        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "concise" -> CONCISE;
            case "detailed" -> DETAILED;
            default -> throw new IllegalArgumentException(
                    "Invalid value for parameter: detail (expected 'concise' or 'detailed')"
            );
        };
    }
}
