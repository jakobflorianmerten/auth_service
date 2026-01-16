package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * DTO für die E-Mail-Verifizierung.
 * Enthält den Verifizierungscode zur Bestätigung der E-Mail-Adresse eines Benutzers.
 */
@Data
public class VerifyEmailRequest {

    /**
     * 6-stelliger Verifizierungscode.
     * Wird per E-Mail an den Benutzer gesendet und muss exakt 6 Ziffern enthalten.
     */
    @NotBlank(message = "Verification code is required")
    @Pattern(regexp = "\\d{6}", message = "Verification code must be 6 digits")
    private String code;
}
