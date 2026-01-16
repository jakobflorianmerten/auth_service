package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO für die Google OAuth-Authentifizierung.
 * Enthält den Google ID-Token zur Verifizierung und Anmeldung über Google.
 */
@Data
public class GoogleTokenRequest {

    /**
     * Google ID-Token.
     * Wird vom Google OAuth-Flow generiert und dient zur Verifizierung der Benutzeridentität.
     */
    @NotBlank(message = "ID token is required")
    private String idToken;
}
