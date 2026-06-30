package ie.atu.ids_service.service;

import ie.atu.ids_service.client.LogInAttemptClient;
import ie.atu.ids_service.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import ie.atu.ids_service.dto.LogInAttemptDTO;
import ie.atu.ids_service.model.Alert;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor

public class DetectionService {
    private final LogInAttemptClient logInAttemptClient;
    private final AlertRepository alertRepository;

private Alert createAlert(String type, String description, String username, String severity) {
    Alert alert = new Alert();
    alert.setAlertType(type);
    alert.setDescription(description);
    alert.setUsername(username);
    alert.setSeverity(severity);
    alert.setTimestamp(LocalDateTime.now());
    return alertRepository.save(alert);
}
// Word-boundary regex avoids false positives on legitimate domains like
// alsatorix.com (contains "or") or doctor@example.com (ends in "or").
// Single-quote and -- are unambiguous SQL tokens so no \b needed there.
private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "'|--|1=1|\\bOR\\b|\\bDROP\\b|\\bSELECT\\b|\\bUNION\\b",
        Pattern.CASE_INSENSITIVE
);

private List<Alert> detectSqlInjection(List<LogInAttemptDTO> attempts) {
    List<Alert> alerts = new ArrayList<>();

    for (LogInAttemptDTO attempt : attempts) {
        if (SQL_INJECTION_PATTERN.matcher(attempt.getUsername()).find()) {
            Alert alert = createAlert(
                    "SQL_INJECTION",
                    "SQL injection attempt detected: " + attempt.getUsername(),
                    attempt.getUsername(),
                    "HIGH"
            );
            alerts.add(alert);
        }
    }
    return alerts;
}
private List<Alert> detectBruteForce(List<LogInAttemptDTO> attempts) {
    List<Alert> alerts = new ArrayList<>();

    Map<String, List<LogInAttemptDTO>> failedByUser = attempts.stream()
            .filter(a -> !a.isSuccess())
            .collect(Collectors.groupingBy(LogInAttemptDTO::getUsername));

    for (Map.Entry<String, List<LogInAttemptDTO>> entry : failedByUser.entrySet()) {
        if (entry.getValue().size() >= 5) {
            Alert alert = createAlert(
                    "BRUTE_FORCE",
                    entry.getValue().size() + " failed login attempts detected for user: " + entry.getKey(),
                    entry.getKey(),
                    "HIGH"
            );
            alerts.add(alert);
        }
    }
    return alerts;
}
public List<Alert> analyzeAttempts() {
    List<LogInAttemptDTO> attempts = logInAttemptClient.getAllAttempts();
    List<Alert> alerts = new ArrayList<>();

    alerts.addAll(detectBruteForce(attempts));
    alerts.addAll(detectSqlInjection(attempts));

    return alerts;
}
}