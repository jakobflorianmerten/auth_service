package com.microservice.auth_service.controller;

import com.microservice.auth_service.dto.request.GoogleTokenRequest;
import com.microservice.auth_service.dto.response.AuthResponse;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.services.GoogleAuthService;
import com.microservice.auth_service.services.JwtService;
import com.microservice.auth_service.services.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller für Google OAuth2 Authentifizierung.
 *
 * Ermöglicht Login/Registrierung via Google Sign-In. Das Frontend führt
 * den Google OAuth-Flow durch und sendet das erhaltene ID-Token an
 * diesen Endpunkt.
 *
 * Flow:
 * 1. Frontend: Google Sign-In → erhält ID-Token
 * 2. Frontend: POST /google mit ID-Token
 * 3. Backend: Validiert Token, erstellt/findet User
 * 4. Backend: Gibt eigene JWTs zurück
 *
 * @see GoogleAuthService
 */
@Slf4j
@RestController
public class GoogleAuthController {

    private final GoogleAuthService googleAuthService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    public GoogleAuthController(
            GoogleAuthService googleAuthService,
            JwtService jwtService,
            RefreshTokenService refreshTokenService
    ) {
        this.googleAuthService = googleAuthService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Authentifiziert einen User mit Google ID-Token.
     *
     * Validiert das Google-Token, erstellt bei Bedarf einen neuen User
     * und gibt Access- und Refresh-Tokens zurück.
     *
     * Account-Linking:
     * - Neuer User: Account wird erstellt
     * - Existierender Google-User: Login erfolgreich
     * - Existierender User ohne Passwort: Account wird mit Google verknüpft
     * - Existierender User mit Passwort: Fehler (409 Conflict)
     *
     * @param request     Google ID-Token vom Frontend
     * @param httpRequest HTTP-Request für Device-Info
     * @return AuthResponse mit Access- und Refresh-Token
     * @throws com.microservice.auth_service.exceptions.InvalidGoogleTokenException wenn Token ungültig (400)
     * @throws com.microservice.auth_service.exceptions.GoogleEmailNotVerifiedException wenn Google-E-Mail nicht verifiziert (400)
     * @throws com.microservice.auth_service.exceptions.UserAlreadyExistsException wenn Account mit Passwort existiert (409)
     */
    @PostMapping("/google")
    public ResponseEntity<AuthResponse> authenticateWithGoogle(
            @Valid @RequestBody GoogleTokenRequest request,
            HttpServletRequest httpRequest
    ) {
        User user = googleAuthService.authenticateWithGoogle(request.getIdToken());

        String deviceInfo = buildDeviceInfo(httpRequest);
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user, deviceInfo);

        log.info("User authenticated via Google: {}", user.getEmail());

        AuthResponse response = AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(accessTokenExpiration / 1000)
                .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Erstellt Device-Info-String aus HTTP-Request.
     *
     * @param request HTTP-Request
     * @return Device-Info-String mit IP und User-Agent
     */
    private String buildDeviceInfo(HttpServletRequest request) {
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        return String.format("IP: %s, User-Agent: %s",
                ip,
                userAgent != null ? userAgent : "unknown"
        );
    }

    /**
     * Extrahiert die Client-IP-Adresse aus dem Request.
     *
     * @param request HTTP-Request
     * @return Client-IP-Adresse
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}