package com.anomaly.platform.ml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.OffsetDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/*
 * Failure classification drives the Kafka retry policy: transient
 * (MlServiceUnavailableException) is retried with backoff, permanent
 * (MlResponseRejectedException) is dead-lettered immediately.
 */
class MlPredictionClientTest {

    private MockRestServiceServer server;
    private MlPredictionClient client;

    private static final MlPredictionRequest REQUEST = new MlPredictionRequest(
            "EV-1", "HOST-1", "LOGIN", "v1", OffsetDateTime.parse("2026-10-02T10:00:00Z"), "rest",
            Map.of("loginSuccess", false));

    private static final String VALID = """
            {"eventId":"EV-1","entityId":"HOST-1","anomalyScore":0.42,"riskScore":42.0,"confidence":null,
             "decision":"NORMAL","modelName":"behavioral-anomaly-ensemble","modelVersion":"pipeline-joblib",
             "attackType":null,"reason":null,"factors":[]}""";

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder().baseUrl("http://ml.test");
        server = MockRestServiceServer.bindTo(builder).build();
        client = new MlPredictionClient(builder.build());
    }

    private void respond(org.springframework.test.web.client.ResponseCreator response) {
        server.expect(requestTo("http://ml.test/predict")).andExpect(method(HttpMethod.POST)).andRespond(response);
    }

    @Test
    void validResponse_isReturned() {
        respond(withSuccess(VALID, MediaType.APPLICATION_JSON));
        assertThat(client.predict(REQUEST).modelName()).isEqualTo("behavioral-anomaly-ensemble");
    }

    // ---- transient: retried ----

    @Test
    void readTimeout_isTransient() {
        respond(withException(new SocketTimeoutException("Read timed out")));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlServiceUnavailableException.class);
    }

    @Test
    void connectionFailure_isTransient() {
        respond(withException(new IOException("Connection refused")));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlServiceUnavailableException.class);
    }

    @Test
    void warmUpResponse_isRecognisedAndTransient() {
        respond(withStatus(HttpStatus.SERVICE_UNAVAILABLE).contentType(MediaType.APPLICATION_JSON)
                .body("{\"detail\":\"ML scorer is still warming up\"}"));
        assertThatThrownBy(() -> client.predict(REQUEST))
                .isInstanceOfSatisfying(MlServiceUnavailableException.class, e -> assertThat(e.isWarmingUp()).isTrue());
    }

    @Test
    void serverError_isTransient_butNotReportedAsWarmUp() {
        respond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"detail\":\"boom\"}"));
        assertThatThrownBy(() -> client.predict(REQUEST))
                .isInstanceOfSatisfying(MlServiceUnavailableException.class, e -> assertThat(e.isWarmingUp()).isFalse());
    }

    // ---- permanent: not retried ----

    @Test
    void clientError_isPermanent() {
        respond(withStatus(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"detail\":\"Input should be a valid string\"}"));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }

    @Test
    void nonJsonBody_isPermanent() {
        respond(withSuccess("<html>gateway</html>", MediaType.TEXT_HTML));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }

    @Test
    void emptyBody_isPermanent() {
        respond(withSuccess("", MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }

    @Test
    void missingOrOutOfRangeScore_isPermanent() {
        respond(withSuccess(VALID.replace("\"anomalyScore\":0.42", "\"anomalyScore\":null"), MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
        server.reset();
        respond(withSuccess(VALID.replace("\"anomalyScore\":0.42", "\"anomalyScore\":1.7"), MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }

    @Test
    void unknownDecision_isPermanent() {
        respond(withSuccess(VALID.replace("\"decision\":\"NORMAL\"", "\"decision\":\"MAYBE\""), MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }

    @Test
    void responseForADifferentEvent_isPermanent() {
        respond(withSuccess(VALID.replace("\"eventId\":\"EV-1\"", "\"eventId\":\"EV-OTHER\""), MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }

    @Test
    void missingModelIdentity_isPermanent() {
        respond(withSuccess(VALID.replace("\"modelVersion\":\"pipeline-joblib\"", "\"modelVersion\":\"\""), MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.predict(REQUEST)).isInstanceOf(MlResponseRejectedException.class);
    }
}
