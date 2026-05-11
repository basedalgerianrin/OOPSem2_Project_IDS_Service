package ie.atu.ids_service.dto;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class LogInAttemptDTO {
    private Long id;
    private String username;
    private String passwordInput;
    private boolean success;
    private LocalDateTime timestamp;

}
