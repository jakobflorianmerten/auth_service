package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für die Benutzer-Registrierung.
 * <p>
 * Enthält die erforderlichen Daten zur Erstellung eines neuen Benutzerkontos.
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    /**
     * E-Mail-Adresse des Benutzers.
     * Muss eine gültige E-Mail-Adresse sein.
     */
    @NotBlank(message = "Email ist erforderlich")
    @Email(message = "Email muss gültig sein")
    private String email;

    /**
     * Passwort für das neue Benutzerkonto.
     * Muss mindestens 8 Zeichen lang sein.
     */
    @NotBlank(message = "Passwort ist erforderlich")
    @Size(min = 8, message = "Passwort muss mindestens 8 Zeichen lang sein")
    private String password;
}
