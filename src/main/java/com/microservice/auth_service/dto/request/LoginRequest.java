package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für die Benutzer-Anmeldung.
 * Enthält die Anmeldedaten zur Authentifizierung eines bestehenden Benutzers.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    /**
     * E-Mail-Adresse des Benutzers.
     * Muss eine gültige E-Mail-Adresse sein.
     */
    @NotBlank(message = "Email ist erforderlich")
    @Email(message = "Email muss gültig sein")
    private String email;

    /**
     * Passwort des Benutzers.
     * Darf nicht leer sein.
     */
    @NotBlank(message = "Passwort ist erforderlich")
    private String password;
}
