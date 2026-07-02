package ie.atu.ids_service.service;

import ie.atu.ids_service.client.LogInAttemptClient;
import ie.atu.ids_service.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import ie.atu.ids_service.dto.LogInAttemptDTO;
import ie.atu.ids_service.model.Alert;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor

public class DetectionService {
    private final LogInAttemptClient logInAttemptClient;
    private final AlertRepository alertRepository;

private static String nz(String s) { return s == null ? "" : s; }   // null-safe IP

// Chronological order; same-second ties broken by id (= insertion order).
private static void sortChronologically(List<LogInAttemptDTO> list) {
    list.sort((x, y) -> {
        LocalDateTime tx = x.getTimestamp(), ty = y.getTimestamp();
        if (tx != null && ty != null && !tx.isEqual(ty)) return tx.compareTo(ty);
        long ix = x.getId() == null ? 0L : x.getId();
        long iy = y.getId() == null ? 0L : y.getId();
        return Long.compare(ix, iy);
    });
}

// Upsert (NOT blind insert): one stored alert per (alertType, username).
// A repeat scan over the same login history re-finds the existing row and
// updates it in place instead of piling up duplicates — so the dashboard's
// alert count reflects distinct findings, not how many times you hit "scan".
private Alert upsertAlert(String type, String description, String username, String severity) {
    Alert alert = alertRepository.findByUsername(username).stream()
            .filter(a -> type.equals(a.getAlertType()))
            .findFirst()
            .orElseGet(Alert::new);   // reuse existing row, or start a new one
    alert.setAlertType(type);
    alert.setDescription(description);
    alert.setUsername(username);
    alert.setSeverity(severity);
    alert.setTimestamp(LocalDateTime.now());
    return alertRepository.save(alert);   // INSERT if id==null, UPDATE if it exists
}

// ----- SQL INJECTION ---------------------------------------------------------
// Word-boundary regex avoids false positives on legitimate domains like
// alsatorix.com (contains "or") or doctor@example.com (ends in "or").
// Single-quote and -- are unambiguous SQL tokens so no \b needed there.
private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "'|--|1=1|\\bOR\\b|\\bDROP\\b|\\bSELECT\\b|\\bUNION\\b",
        Pattern.CASE_INSENSITIVE
);

// Severity = confidence the input is a real exploit (see classify below).
private String classifySqliSeverity(String username) {
    String upper = username.toUpperCase();
    boolean hasQuote    = username.contains("'");
    boolean hasComment  = username.contains("--");
    boolean hasEquality = username.contains("1=1");
    boolean hasOr     = upper.matches(".*\\bOR\\b.*");
    boolean hasSelect = upper.matches(".*\\bSELECT\\b.*");
    boolean hasUnion  = upper.matches(".*\\bUNION\\b.*");
    boolean hasDrop   = upper.matches(".*\\bDROP\\b.*");

    if (hasUnion || hasDrop || hasEquality || (hasQuote && (hasOr || hasComment))) {
        return "HIGH";   // classic signature: UNION/DROP/1=1, or quote + OR/comment
    }
    if (hasOr || hasSelect || hasComment) {
        return "MEDIUM"; // a clear SQL token, but not a wrapped exploit
    }
    return "LOW";        // only an ambiguous token (lone quote) — could be O'Brien
}

private List<Alert> detectSqlInjection(List<LogInAttemptDTO> attempts) {
    List<Alert> alerts = new ArrayList<>();
    for (LogInAttemptDTO attempt : attempts) {
        if (SQL_INJECTION_PATTERN.matcher(attempt.getUsername()).find()) {
            String severity = classifySqliSeverity(attempt.getUsername());
            alerts.add(upsertAlert(
                    "SQL_INJECTION",
                    "SQL injection attempt detected (" + severity + " confidence): "
                            + attempt.getUsername(),
                    attempt.getUsername(),
                    severity));
        }
    }
    return alerts;
}

// ----- BRUTE FORCE (IP- and chronology-aware) --------------------------------
// Severity weighs WHERE the attempts came from and WHEN the success happened,
// not just how many:
//   CRITICAL - once the failure streak already existed (>=5 fails), a login
//              SUCCEEDED from an IP that produced none of those failures
//              (takeover), or 20+ failures that then succeeded (cracked).
//   HIGH     - failures from >=3 distinct known IPs (distributed / credential
//              stuffing), or 20+ failures with no subsequent success.
//   MEDIUM   - 10-19 failures from a single IP.
//   LOW      - 5-9 failures; if a success followed FROM THE SAME IP, that's the
//              "client forgot their password" shape, not an attack.
// A success BEFORE the failures started is the user's normal login and must
// not count as a takeover. Attempts with no recorded IP (rows that predate IP
// capture) carry no location signal: they are never counted as a distinct IP
// and can neither trigger nor suppress the new-IP takeover rule.
private List<Alert> detectBruteForce(List<LogInAttemptDTO> attempts) {
    List<Alert> alerts = new ArrayList<>();
    Map<String, List<LogInAttemptDTO>> byUser = attempts.stream()
            .collect(Collectors.groupingBy(LogInAttemptDTO::getUsername));

    for (Map.Entry<String, List<LogInAttemptDTO>> entry : byUser.entrySet()) {
        String user = entry.getKey();
        List<LogInAttemptDTO> ordered = new ArrayList<>(entry.getValue());
        sortChronologically(ordered);

        int fails = 0;
        Set<String> failIps = new HashSet<>();   // known IPs that produced failures
        boolean succeededAfterFails = false;     // a success once the streak (>=5) existed
        boolean successFromNewIp = false;        // ...from an IP with none of those failures

        for (LogInAttemptDTO a : ordered) {
            String ip = nz(a.getIp());
            if (!a.isSuccess()) {
                fails++;
                if (!ip.isEmpty()) failIps.add(ip);
            } else if (fails >= 5) {
                succeededAfterFails = true;
                if (!ip.isEmpty() && !failIps.isEmpty() && !failIps.contains(ip)) {
                    successFromNewIp = true;
                }
            }
        }
        if (fails < 5) {
            continue;   // below the brute-force threshold
        }
        int nIps = failIps.size();

        String severity;
        String reason;
        if (successFromNewIp) {
            severity = "CRITICAL";
            reason = "after " + fails + " failures a login succeeded from an IP that produced none of them — likely account takeover";
        } else if (nIps >= 3) {
            severity = "HIGH";
            reason = fails + " failures from " + nIps + " distinct IPs — distributed / credential-stuffing pattern";
        } else if (fails >= 20) {
            severity = succeededAfterFails ? "CRITICAL" : "HIGH";
            reason = succeededAfterFails
                    ? fails + " failures then a success from the same IP — password likely cracked"
                    : fails + " failed attempts from a single IP";
        } else if (fails >= 10) {
            severity = "MEDIUM";
            reason = fails + " failed attempts" + (succeededAfterFails ? " then a success" : "") + " from a single IP";
        } else {   // 5-9 failures
            severity = "LOW";
            reason = succeededAfterFails
                    ? fails + " failures then a successful login from the same IP — likely a legitimate user who forgot their password"
                    : fails + " failed attempts from a single IP";
        }

        alerts.add(upsertAlert(
                "BRUTE_FORCE",
                "Brute force (" + severity + "): " + reason + " [user: " + user + "]",
                user,
                severity));
    }
    return alerts;
}

// ----- NEW LOCATION (impossible-travel-lite) ---------------------------------
// Flags a SUCCESSFUL login from an IP a user has never used before — but ONLY
// once they already have a history from some other IP. A brand-new account's
// first login has no baseline, so it is NOT flagged (that would alert on every
// legitimate first sign-in). Always LOW: informational, for correlation.
private List<Alert> detectNewLocation(List<LogInAttemptDTO> attempts) {
    List<Alert> alerts = new ArrayList<>();
    Map<String, List<LogInAttemptDTO>> byUser = attempts.stream()
            .collect(Collectors.groupingBy(LogInAttemptDTO::getUsername));

    for (Map.Entry<String, List<LogInAttemptDTO>> entry : byUser.entrySet()) {
        String user = entry.getKey();
        List<LogInAttemptDTO> ordered = new ArrayList<>(entry.getValue());
        sortChronologically(ordered);

        Set<String> seenIps = new HashSet<>();
        for (LogInAttemptDTO a : ordered) {
            String ip = nz(a.getIp());
            if (a.isSuccess() && !ip.isEmpty() && !seenIps.isEmpty() && !seenIps.contains(ip)) {
                alerts.add(upsertAlert(
                        "NEW_LOCATION",
                        "Successful login from a new source IP (" + ip
                                + ") for an account with prior activity elsewhere [user: " + user + "]",
                        user,
                        "LOW"));
                break;   // one new-location flag per user is enough
            }
            // Rows without a recorded IP carry no location signal — adding ""
            // would create a phantom baseline and false-flag the first real IP.
            if (!ip.isEmpty()) {
                seenIps.add(ip);
            }
        }
    }
    return alerts;
}

public List<Alert> analyzeAttempts() {
    List<LogInAttemptDTO> attempts = logInAttemptClient.getAllAttempts();
    List<Alert> alerts = new ArrayList<>();

    alerts.addAll(detectBruteForce(attempts));
    alerts.addAll(detectSqlInjection(attempts));
    alerts.addAll(detectNewLocation(attempts));

    // Collapse the return value by alert id so the scan response matches the
    // deduped stored table (several source attempts can map to one alert row).
    Map<Long, Alert> distinct = new LinkedHashMap<>();
    for (Alert a : alerts) {
        distinct.put(a.getId(), a);
    }
    return new ArrayList<>(distinct.values());
}
}
