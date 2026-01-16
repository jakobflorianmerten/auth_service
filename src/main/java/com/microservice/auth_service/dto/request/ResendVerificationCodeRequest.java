package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO für das erneute Senden des Verifizierungscodes.
 * Ermöglicht es Benutzern, einen neuen Verifizierungscode anzufordern,
 * falls der ursprüngliche Code abgelaufen ist oder nicht empfangen wurde.
 */
@Data
public class ResendVerificationCodeRequest {

    /**
     * E-Mail-Adresse des Benutzers.
     * An diese Adresse wird ein neuer Verifizierungscode gesendet.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    private String email;
}