package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für die Anforderung eines Passwort-Resets.
 * Initiiert den Passwort-Reset-Prozess durch Senden eines Reset-Codes an die angegebene E-Mail-Adresse.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RequestPasswordResetRequest {

    /**
     * E-Mail-Adresse des Benutzers.
     * An diese Adresse wird der Passwort-Reset-Code gesendet.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    private String email;
}