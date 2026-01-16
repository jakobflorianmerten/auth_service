package com.microservice.auth_service.controller;

import com.microservice.auth_service.dto.request.RequestPasswordResetRequest;
import com.microservice.auth_service.dto.request.ResetPasswordRequest;
import com.microservice.auth_service.dto.response.MessageResponse;
import com.microservice.auth_service.services.UserService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller für Passwort-Reset-Flow.
 *
 * Stellt Endpunkte für das Zurücksetzen vergessener Passwörter bereit:
 * - Reset-Code anfordern (sendet E-Mail)
 * - Passwort mit Code zurücksetzen
 *
 * Sicherheitshinweis: Der /request-password-reset Endpunkt gibt immer
 * die gleiche Response zurück, unabhängig davon, ob die E-Mail existiert.
 * Dies verhindert User-Enumeration.
 *
 * @see UserService
 */
@Slf4j
@RestController
public class PasswordResetController {

    private final UserService userService;

    public PasswordResetController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Fordert einen Passwort-Reset an.
     *
     * Sendet eine E-Mail mit Reset-Code an die angegebene Adresse,
     * falls ein Account mit dieser E-Mail existiert.
     *
     * Sicherheit: Gibt immer 200 OK zurück, auch wenn die E-Mail
     * nicht existiert. Dies verhindert, dass Angreifer herausfinden
     * können, welche E-Mail-Adressen registriert sind.
     *
     * @param request E-Mail-Adresse
     * @return Bestätigungsnachricht (immer gleich)
     */
    @PostMapping("/request-password-reset")
    public ResponseEntity<MessageResponse> requestPasswordReset(
            @Valid @RequestBody RequestPasswordResetRequest request
    ) {
        userService.requestPasswordReset(request.getEmail());

        log.debug("Password reset requested for: {}", request.getEmail());

        MessageResponse response = MessageResponse.builder()
                .message("If the email exists, a password reset code has been sent")
                .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Setzt das Passwort mit einem gültigen Reset-Code zurück.
     *
     * Nach erfolgreichem Reset werden alle bestehenden Refresh-Tokens
     * des Users widerrufen (erzwingt Neuanmeldung auf allen Geräten).
     *
     * @param request Reset-Code und neues Passwort
     * @return Bestätigungsnachricht
     * @throws com.microservice.auth_service.exceptions.InvalidPasswordResetCodeException wenn Code ungültig (400)
     * @throws com.microservice.auth_service.exceptions.PasswordResetCodeExpiredException wenn Code abgelaufen (410)
     */
    @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        userService.resetPassword(request.getCode(), request.getNewPassword());

        log.info("Password reset completed");

        MessageResponse response = MessageResponse.builder()
                .message("Password has been successfully reset")
                .build();

        return ResponseEntity.ok(response);
    }
}