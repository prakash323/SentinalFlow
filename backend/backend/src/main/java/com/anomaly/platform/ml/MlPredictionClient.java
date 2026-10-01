package com.anomaly.platform.ml;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/*
 * Thin HTTP client for the SentinelFlow ML service (api.py).
 *
 * Deliberately has no try/catch: RestClient throws an unchecked
 * RestClientException (ResourceAccessException for connect/read timeouts
 * and connection failures, RestClientResponseException for non-2xx
 * responses such as the 503 api.py returns while the model is still
 * warming up, or the 500 it returns on an internal scoring error). Letting
 * that propagate is what lets EventProcessingService's existing ledger/
 * Kafka retry-and-DLT handling (built in Phase 1) take over without any
 * ML-specific error handling duplicated here.
 */
@Service
public class MlPredictionClient {

    private final RestClient restClient;

    public MlPredictionClient(RestClient mlRestClient) {
        this.restClient = mlRestClient;
    }

    public MlPredictionResponse predict(MlPredictionRequest request) {

        return restClient.post()
                .uri("/predict")
                .body(request)
                .retrieve()
                .body(MlPredictionResponse.class);
    }
}
