package com.microservice.auth_service.controller;

import com.microservice.auth_service.dto.request.RegisterRequest;
import com.microservice.auth_service.dto.response.RegisterResponse;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.services.UserService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller für User-Registrierung.
 *
 * Stellt den Endpunkt für neue Benutzerregistrierungen bereit.
 * Nach erfolgreicher Registrierung wird eine Verifizierungs-E-Mail
 * gesendet. Der Account ist erst nach E-Mail-Verifizierung aktiv.
 *
 * @see UserService#registerUser
 */
@Slf4j
@RestController
public class RegistrationController {

    private final UserService userService;

    public RegistrationController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Registriert einen neuen User.
     *
     * Erstellt einen deaktivierten Account und sendet eine
     * Verifizierungs-E-Mail. Der User muss seine E-Mail bestätigen,
     * bevor er sich anmelden kann.
     *
     * @param request Registrierungsdaten (Email, Passwort)
     * @return 201 Created mit Bestätigungsnachricht
     * @throws com.microservice.auth_service.exceptions.UserAlreadyExistsException wenn E-Mail bereits registriert (409)
     */
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        User user = userService.registerUser(request);

        log.info("User registered: {}", user.getEmail());

        RegisterResponse response = RegisterResponse.builder()
                .message("Registration successful. Please check your email for verification code.")
                .email(user.getEmail())
                .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}