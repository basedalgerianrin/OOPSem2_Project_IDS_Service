package ie.atu.ids_service.client;

import ie.atu.ids_service.dto.LogInAttemptDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import java.util.List;


// The attempts feed now lives in the Alsatorix FastAPI app, not the old
// Web_target. The URL is externalised (web-target.url / WEB_TARGET_URL) so the
// same jar works locally (localhost:8081) and in Docker (http://alsatorix:8080).
// FeignConfig attaches the X-IDS-Token shared secret to every request.
@FeignClient(
        name = "web-target",
        url = "${web-target.url:http://localhost:8081}",
        configuration = FeignConfig.class
)
public interface LogInAttemptClient {
    @GetMapping("/api/attempts")
    List<LogInAttemptDTO> getAllAttempts();
    @GetMapping("/api/attempts/failed")
    List<LogInAttemptDTO> getFailedAttempts();

    @GetMapping("/api/attempts/user/{username}")
    List<LogInAttemptDTO> getAttemptsByUser(@PathVariable String username);
}
