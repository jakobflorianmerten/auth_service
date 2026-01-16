package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für das Zurücksetzen des Passworts.
 * Enthält den Reset-Code und das neue Passwort zur Durchführung des Passwort-Resets.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordRequest {

    /**
     * 6-stelliger Reset-Code.
     * Wurde per E-Mail an den Benutzer gesendet und bestätigt die Berechtigung zum Passwort-Reset.
     */
    @NotBlank(message = "Reset code is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "Reset code must be 6 digits")
    private String code;

    /**
     * Neues Passwort für das Benutzerkonto.
     * Muss mindestens 8 Zeichen lang sein.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String newPassword;
}