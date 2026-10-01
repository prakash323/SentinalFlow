package com.anomaly.platform.ml;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
@EnableConfigurationProperties(MlServiceProperties.class)
public class MlClientConfig {

    /*
     * IMPORTANT: build from the injected, Boot-autoconfigured
     * RestClient.Builder, not the static RestClient.builder() factory.
     * The static factory creates a brand-new builder with a bare default
     * Jackson ObjectMapper, which serialises OffsetDateTime as a raw
     * epoch number (jackson-datatype-jsr310's own default) instead of an
     * ISO-8601 string - api.py's Pydantic model then rejects it with a
     * 422 ("Input should be a valid string"). The autoconfigured builder
     * already carries the application's real Jackson configuration
     * (ISO-8601 dates), exactly like every other JSON body this
     * application sends or receives.
     */
    @Bean
    public RestClient mlRestClient(RestClient.Builder builder, MlServiceProperties props) {

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout((int) props.getConnectTimeout().toMillis());
        factory.setReadTimeout((int) props.getReadTimeout().toMillis());

        return builder
                .baseUrl(props.getUrl())
                .requestFactory(factory)
                .build();
    }
}
