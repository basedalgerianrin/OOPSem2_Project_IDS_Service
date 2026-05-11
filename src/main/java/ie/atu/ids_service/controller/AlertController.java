package ie.atu.ids_service.controller;

import ie.atu.ids_service.model.Alert;
import ie.atu.ids_service.repository.AlertRepository;
import ie.atu.ids_service.service.DetectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertController {

    private final AlertRepository alertRepository;
    private final DetectionService detectionService;

    // GET /api/alerts — return all alerts in the database
    @GetMapping
    public List<Alert> getAllAlerts() {
        return alertRepository.findAll();
    }

    // GET /api/alerts/{id} — return one alert by its ID
    @GetMapping("/{id}")
    public ResponseEntity<Alert> getAlertById(@PathVariable Long id) {
        return alertRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // GET /api/alerts/user/{username} — return all alerts for a specific user
    @GetMapping("/user/{username}")
    public List<Alert> getAlertsByUsername(@PathVariable String username) {
        return alertRepository.findByUsername(username);
    }

    // GET /api/alerts/analyze — triggers the IDS scan and returns new alerts
    @GetMapping("/analyze")
    public List<Alert> analyzeAttempts() {
        return detectionService.analyzeAttempts();
    }
}
