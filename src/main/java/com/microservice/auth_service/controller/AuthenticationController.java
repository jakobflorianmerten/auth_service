package com.microservice.auth_service.controller;

import com.microservice.auth_service.dto.request.LoginRequest;
import com.microservice.auth_service.dto.request.LogoutRequest;
import com.microservice.auth_service.dto.response.AuthResponse;
import com.microservice.auth_service.exceptions.InvalidAuthorizationHeaderException;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.services.JwtService;
import com.microservice.auth_service.services.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller für Authentifizierungs-Endpunkte.
 *
 * Stellt folgende Endpunkte bereit:
 * - POST /login: Benutzer-Anmeldung mit Email/Passwort
 * - POST /refresh: Access-Token erneuern mit Refresh-Token
 * - POST /logout: Refresh-Token widerrufen
 *
 * Alle Endpunkte geben bei Erfolg eine AuthResponse mit Tokens zurück
 * oder werfen spezifische Exceptions, die vom GlobalExceptionHandler
 * behandelt werden.
 *
 * @see AuthResponse
 * @see com.microservice.auth_service.exceptions.GlobalExceptionHandler
 */
@Slf4j
@RestController
public class AuthenticationController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    public AuthenticationController(
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            RefreshTokenService refreshTokenService
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Authentifiziert einen User mit Email und Passwort.
     *
     * Bei erfolgreicher Authentifizierung werden Access- und Refresh-Token
     * generiert. Der Refresh-Token wird mit Geräteinformationen (IP-Adresse)
     * gespeichert.
     *
     * @param request     Login-Daten (Email, Passwort)
     * @param httpRequest HTTP-Request für IP-Extraktion
     * @return AuthResponse mit Access- und Refresh-Token
     * @throws org.springframework.security.authentication.BadCredentialsException bei falschen Credentials
     * @throws org.springframework.security.authentication.DisabledException wenn Account deaktiviert
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = (User) authentication.getPrincipal();
        String deviceInfo = buildDeviceInfo(httpRequest);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user, deviceInfo);

        log.info("User logged in: {}", user.getEmail());

        return ResponseEntity.ok(buildAuthResponse(accessToken, refreshToken));
    }

    /**
     * Erneuert den Access-Token mit einem gültigen Refresh-Token.
     *
     * Der Refresh-Token muss im Authorization-Header als Bearer-Token
     * übergeben werden. Bei erfolgreicher Validierung wird ein neuer
     * Access-Token ausgestellt.
     *
     * @param authHeader Authorization-Header mit Refresh-Token
     * @return AuthResponse mit neuem Access-Token
     * @throws InvalidAuthorizationHeaderException wenn Header-Format ungültig
     * @throws com.microservice.auth_service.exceptions.InvalidRefreshTokenException wenn Token ungültig/abgelaufen
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @RequestHeader("Authorization") String authHeader
    ) {
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new InvalidAuthorizationHeaderException();
        }

        String refreshToken = authHeader.substring(BEARER_PREFIX.length());
        User user = refreshTokenService.validateAndUseToken(refreshToken);
        refreshTokenService.revokeTokenForUser(refreshToken, user);

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = refreshTokenService.createRefreshToken(user, null);

        log.debug("Access token refreshed for user: {}", user.getEmail());

        return ResponseEntity.ok(buildAuthResponse(newAccessToken, newRefreshToken));
    }

    /**
     * Meldet einen User ab und widerruft den Refresh-Token.
     *
     * Erfordert Authentifizierung via Access-Token im Authorization-Header.
     * Der zu widerrufende Refresh-Token muss im Request-Body übergeben werden
     * und dem authentifizierten User gehören.
     *
     * @param user    authentifizierter User aus dem Security-Context
     * @param request Logout-Daten mit Refresh-Token
     * @return 200 OK bei Erfolg
     * @throws com.microservice.auth_service.exceptions.InvalidRefreshTokenException wenn Token ungültig oder nicht dem User gehört
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody LogoutRequest request
    ) {
        refreshTokenService.revokeTokenForUser(request.getRefreshToken(), user);

        log.info("User logged out: {}", user.getEmail());

        return ResponseEntity.ok().build();
    }

    /**
     * Erstellt eine AuthResponse mit den übergebenen Tokens.
     *
     * @param accessToken  JWT Access-Token
     * @param refreshToken Refresh-Token
     * @return AuthResponse
     */
    private AuthResponse buildAuthResponse(String accessToken, String refreshToken) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(accessTokenExpiration / 1000)
                .build();
    }

    /**
     * Erstellt Device-Info-String aus HTTP-Request.
     *
     * Enthält IP-Adresse und User-Agent für Session-Tracking.
     *
     * @param request HTTP-Request
     * @return Device-Info-String
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
     * Berücksichtigt Proxy-Header (X-Forwarded-For, X-Real-IP)
     * für korrekte IP-Ermittlung hinter Load-Balancern.
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