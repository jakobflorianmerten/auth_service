package com.microservice.auth_service.controller;

import com.microservice.auth_service.dto.request.ResendVerificationCodeRequest;
import com.microservice.auth_service.dto.request.VerifyEmailRequest;
import com.microservice.auth_service.dto.response.AuthResponse;
import com.microservice.auth_service.dto.response.MessageResponse;
import com.microservice.auth_service.services.UserService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller für E-Mail-Verifizierung.
 *
 * Stellt Endpunkte für die Verifizierung von E-Mail-Adressen bereit:
 * - Verifizierungscode validieren und Account aktivieren
 * - Verifizierungscode erneut senden
 *
 * Nach erfolgreicher Verifizierung wird der User automatisch eingeloggt
 * und erhält Access- und Refresh-Tokens.
 *
 * @see UserService
 */
@Slf4j
@RestController
public class EmailVerificationController {

    private final UserService userService;

    public EmailVerificationController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Verifiziert eine E-Mail-Adresse mit dem zugesendeten Code.
     *
     * Bei erfolgreicher Verifizierung wird der Account aktiviert und
     * der User automatisch eingeloggt (Auto-Login).
     *
     * @param request Verifizierungscode
     * @return AuthResponse mit Access- und Refresh-Token
     * @throws com.microservice.auth_service.exceptions.InvalidVerificationCodeException wenn Code ungültig (400)
     * @throws com.microservice.auth_service.exceptions.VerificationCodeExpiredException wenn Code abgelaufen (410)
     */
    @PostMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request
    ) {
        AuthResponse response = userService.verifyEmail(request.getCode());

        log.info("Email verified successfully");

        return ResponseEntity.ok(response);
    }

    /**
     * Sendet den Verifizierungscode erneut.
     *
     * Generiert einen neuen Code und sendet ihn an die angegebene
     * E-Mail-Adresse. Der vorherige Code wird dabei ungültig.
     *
     * @param request E-Mail-Adresse des Users
     * @return Bestätigungsnachricht
     * @throws com.microservice.auth_service.exceptions.UserNotFoundException wenn User nicht existiert (404)
     * @throws com.microservice.auth_service.exceptions.EmailAlreadyVerifiedException wenn E-Mail bereits verifiziert (400)
     */
    @PostMapping("/resend-verification-code")
    public ResponseEntity<MessageResponse> resendVerificationCode(
            @Valid @RequestBody ResendVerificationCodeRequest request
    ) {
        userService.resendVerificationCode(request.getEmail());

        log.debug("Verification code resent to: {}", request.getEmail());

        MessageResponse response = MessageResponse.builder()
                .message("Verification code sent successfully")
                .build();

        return ResponseEntity.ok(response);
    }
}