package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.InvalidRefreshTokenException;
import com.microservice.auth_service.model.RefreshToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.RefreshTokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

/**
 * Service für Refresh-Token-Verwaltung.
 *
 * Refresh-Tokens ermöglichen das Erneuern von Access-Tokens ohne erneute
 * Anmeldung. Sie sind langlebiger als Access-Tokens (Standard: 7 Tage)
 * und werden sicher in der Datenbank gespeichert.
 *
 * Sicherheitskonzept:
 * - Tokens werden als SHA-256 Hash gespeichert (nicht im Klartext)
 * - Client erhält den Klartext-Token nur einmal bei Erstellung
 * - Tokens können einzeln oder pro User widerrufen werden
 * - Abgelaufene Tokens werden automatisch bereinigt
 *
 * Konfiguration via application.yaml:
 * - jwt.refresh-token-expiration: Gültigkeit in Millisekunden (Standard: 7 Tage)
 *
 * Hinweis: Erfordert @EnableScheduling in einer Configuration-Klasse
 * für die automatische Token-Bereinigung.
 *
 * @see RefreshToken
 */
@Slf4j
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-token-expiration:604800000}")
    private long refreshTokenExpiration;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * Erstellt einen neuen Refresh-Token für einen User.
     *
     * Generiert einen UUID-basierten Token, speichert dessen Hash in der
     * Datenbank und gibt den Klartext-Token zurück. Der Client sieht den
     * Klartext nur dieses eine Mal.
     *
     * @param user       User, für den der Token erstellt wird
     * @param deviceInfo optionale Geräteinformationen (User-Agent, IP, etc.)
     * @return Klartext-Token für den Client
     */
    @Transactional
    public String createRefreshToken(User user, String deviceInfo) {
        String token = UUID.randomUUID().toString();
        String tokenHash = hashToken(token);

        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(refreshTokenExpiration / 1000);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(tokenHash)
                .user(user)
                .expiresAt(expiresAt)
                .deviceInfo(deviceInfo)
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
        log.debug("Refresh token created for user: {}", user.getEmail());

        return token;
    }

    /**
     * Validiert einen Refresh-Token und aktualisiert den Last-Used-Timestamp.
     *
     * Prüft:
     * - Token existiert in der Datenbank
     * - Token ist nicht abgelaufen
     * - Token ist nicht widerrufen
     *
     * @param token Klartext-Token vom Client
     * @return User, dem der Token gehört
     * @throws InvalidRefreshTokenException wenn Token ungültig, abgelaufen oder widerrufen
     */
    @Transactional
    public User validateAndUseToken(String token) {
        String tokenHash = hashToken(token);

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Refresh token validation failed: token not found");
                    return new InvalidRefreshTokenException();
                });

        if (!refreshToken.isValid()) {
            log.warn("Refresh token validation failed: token expired or revoked for user {}",
                    refreshToken.getUser().getEmail());
            throw new InvalidRefreshTokenException();
        }

        refreshToken.setLastUsedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

        log.debug("Refresh token validated for user: {}", refreshToken.getUser().getEmail());
        return refreshToken.getUser();
    }

    /**
     * Widerruft einen spezifischen Refresh-Token.
     *
     * Prüft, ob der Token dem angegebenen User gehört, um zu verhindern,
     * dass User fremde Tokens widerrufen können.
     *
     * @param token Klartext-Token zum Widerrufen
     * @param user  User, dem der Token gehören muss
     * @throws InvalidRefreshTokenException wenn Token nicht existiert oder nicht dem User gehört
     */
    @Transactional
    public void revokeTokenForUser(String token, User user) {
        String tokenHash = hashToken(token);

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Token revocation failed: token not found for user {}", user.getEmail());
                    return new InvalidRefreshTokenException();
                });

        if (!refreshToken.getUser().getId().equals(user.getId())) {
            log.warn("Token revocation failed: token does not belong to user {}", user.getEmail());
            throw new InvalidRefreshTokenException();
        }

        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        log.info("Refresh token revoked for user: {}", user.getEmail());
    }

    /**
     * Widerruft alle Refresh-Tokens eines Users.
     *
     * Nützlich für:
     * - "Logout from all devices"
     * - Passwort-Änderung
     * - Account-Kompromittierung
     *
     * @param user User, dessen Tokens widerrufen werden
     */
    @Transactional
    public void revokeAllTokensForUser(User user) {
        refreshTokenRepository.revokeAllByUser(user);
        log.info("All refresh tokens revoked for user: {}", user.getEmail());
    }

    /**
     * Löscht alle abgelaufenen Tokens aus der Datenbank.
     *
     * Läuft täglich um 3:00 Uhr. Erfordert @EnableScheduling.
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        log.info("Expired refresh tokens cleaned up: {} deleted", deleted);
    }

    /**
     * Hasht einen Token mit SHA-256.
     *
     * @param token Klartext-Token
     * @return Base64-codierter SHA-256 Hash
     * @throws IllegalStateException wenn SHA-256 nicht verfügbar (sollte nie passieren)
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 ist in jeder JVM verfügbar, sollte nie passieren
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}