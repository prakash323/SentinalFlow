package com.anomaly.platform.ml;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.math.BigDecimal;

/*
 * Thin HTTP client for the SentinelFlow ML service (api.py).
 *
 * Every failure is classified so the Kafka error handler can decide whether
 * retrying the same event can help (KafkaErrorHandlingConfig):
 *
 *   transient -> MlServiceUnavailableException (retried with backoff)
 *     - connection refused/reset, connect or read timeout
 *       (ResourceAccessException)
 *     - any HTTP 5xx, including api.py's warm-up response
 *       (503 "ML scorer is still warming up")
 *
 *   permanent -> MlResponseRejectedException (dead-lettered, no retry)
 *     - any HTTP 4xx: the request itself was rejected (e.g. 422 validation)
 *     - a 2xx whose body cannot be read, or fails validate() below
 *
 * The ML service owns the model; this only checks the response is usable
 * as a prediction, it never second-guesses scores or decisions.
 */
@Service
public class MlPredictionClient {

    private static final String WARM_UP_MARKER = "warming up";

    private final RestClient restClient;

    public MlPredictionClient(RestClient mlRestClient) {
        this.restClient = mlRestClient;
    }

    public MlPredictionResponse predict(MlPredictionRequest request) {

        MlPredictionResponse response;

        try {
            response = restClient.post()
                    .uri("/predict")
                    .body(request)
                    .retrieve()
                    .body(MlPredictionResponse.class);

        } catch (ResourceAccessException unreachable) {
            throw new MlServiceUnavailableException(
                    "ML service unreachable or timed out: " + unreachable.getMessage(), false, unreachable);

        } catch (HttpServerErrorException serverError) {
            boolean warmingUp = serverError.getStatusCode().isSameCodeAs(HttpStatus.SERVICE_UNAVAILABLE)
                    && serverError.getResponseBodyAsString().contains(WARM_UP_MARKER);
            throw new MlServiceUnavailableException(
                    (warmingUp ? "ML service is warming up: " : "ML service error: ") + serverError.getMessage(),
                    warmingUp,
                    serverError);

        } catch (HttpClientErrorException clientError) {
            throw new MlResponseRejectedException(
                    "ML service rejected the request: " + clientError.getMessage(), clientError);

        } catch (RestClientException unreadable) {
            // e.g. a 2xx body that is not valid JSON for MlPredictionResponse
            throw new MlResponseRejectedException(
                    "Unreadable ML service response: " + unreadable.getMessage(), unreadable);
        }

        validate(request, response);
        return response;
    }

    private static void validate(MlPredictionRequest request, MlPredictionResponse response) {

        if (response == null) {
            throw new MlResponseRejectedException("Empty ML service response for eventId=" + request.eventId());
        }
        if (response.eventId() != null && !response.eventId().equals(request.eventId())) {
            throw new MlResponseRejectedException(
                    "ML response is for eventId=" + response.eventId() + ", expected " + request.eventId());
        }
        BigDecimal score = response.anomalyScore();
        if (score == null || score.compareTo(BigDecimal.ZERO) < 0 || score.compareTo(BigDecimal.ONE) > 0) {
            throw new MlResponseRejectedException(
                    "ML response has a missing or out-of-range anomalyScore (" + score + ") for eventId=" + request.eventId());
        }
        if (!"ANOMALOUS".equalsIgnoreCase(response.decision()) && !"NORMAL".equalsIgnoreCase(response.decision())) {
            throw new MlResponseRejectedException(
                    "ML response has an unknown decision '" + response.decision() + "' for eventId=" + request.eventId());
        }
        if (isBlank(response.modelName()) || isBlank(response.modelVersion())) {
            throw new MlResponseRejectedException(
                    "ML response is missing modelName/modelVersion for eventId=" + request.eventId());
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
