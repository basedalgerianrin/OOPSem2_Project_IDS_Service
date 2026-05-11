package ie.atu.ids_service.client;

import ie.atu.ids_service.dto.LogInAttemptDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import java.util.List;


@FeignClient(name= "web-target", url = "http://localhost:8081")
public interface LogInAttemptClient {
    @GetMapping("/api/attempts")
    List<LogInAttemptDTO> getAllAttempts();
    @GetMapping("/api/attempts/failed")
    List<LogInAttemptDTO> getFailedAttempts();

    @GetMapping("/api/attempts/user/{username}")
    List<LogInAttemptDTO> getAttemptsByUser(@PathVariable String username);
}
