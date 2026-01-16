package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für die Benutzer-Abmeldung.
 * Enthält den Refresh-Token, der bei der Abmeldung invalidiert werden soll.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogoutRequest {

    /**
     * Refresh-Token des Benutzers.
     * Wird bei der Abmeldung invalidiert, um weitere Token-Erneuerungen zu verhindern.
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}