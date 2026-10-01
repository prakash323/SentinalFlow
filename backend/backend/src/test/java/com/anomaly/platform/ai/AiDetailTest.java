package com.anomaly.platform.ai;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiDetailTest {

    @Test
    void absentOrBlank_isConcise() {
        assertThat(AiDetail.parse(null)).isEqualTo(AiDetail.CONCISE);
        assertThat(AiDetail.parse("")).isEqualTo(AiDetail.CONCISE);
        assertThat(AiDetail.parse("   ")).isEqualTo(AiDetail.CONCISE);
    }

    @Test
    void knownValues_areCaseInsensitive() {
        assertThat(AiDetail.parse("concise")).isEqualTo(AiDetail.CONCISE);
        assertThat(AiDetail.parse("detailed")).isEqualTo(AiDetail.DETAILED);
        assertThat(AiDetail.parse(" Detailed ")).isEqualTo(AiDetail.DETAILED);
        assertThat(AiDetail.parse("DETAILED")).isEqualTo(AiDetail.DETAILED);
    }

    @Test
    void anythingElse_isRejected_notSilentlyTreatedAsAValidMode() {
        assertThatThrownBy(() -> AiDetail.parse("verbose"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("detail");
    }
}
