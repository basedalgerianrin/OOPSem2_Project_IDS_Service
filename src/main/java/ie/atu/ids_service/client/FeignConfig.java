package ie.atu.ids_service.client;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Feign configuration for the attempts-feed client.
 *
 * The Alsatorix /api/attempts endpoint is shared-secret protected (it exposes
 * admin login history), so every outbound request carries the secret in an
 * X-IDS-Token header. The value comes from ids.shared-secret / IDS_SHARED_SECRET
 * and must match what the FastAPI app is configured with.
 */
@Configuration
public class FeignConfig {

    @Value("${ids.shared-secret:}")
    private String sharedSecret;

    @Bean
    public RequestInterceptor idsTokenInterceptor() {
        return template -> {
            if (sharedSecret != null && !sharedSecret.isBlank()) {
                template.header("X-IDS-Token", sharedSecret);
            }
        };
    }
}
