package com.microservice.auth_service.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Entity für Refresh-Tokens zur Session-Verwaltung.
 *
 * Refresh-Tokens ermöglichen das Erneuern von Access-Tokens ohne erneute
 * Anmeldung. Sie werden als SHA-256 Hash gespeichert (nicht im Klartext).
 *
 * Lebenszyklus:
 * 1. Token wird bei Login/Registrierung erstellt
 * 2. Client verwendet Token zum Erneuern des Access-Tokens
 * 3. Token wird bei Logout oder Password-Reset widerrufen
 * 4. Abgelaufene Tokens werden vom Cleanup-Job gelöscht
 *
 * Sicherheitsfeatures:
 * - Nur Hash wird gespeichert, nicht der Klartext-Token
 * - Tokens können einzeln oder pro User widerrufen werden
 * - lastUsedAt ermöglicht Erkennung inaktiver Sessions
 *
 * @see com.microservice.auth_service.services.RefreshTokenService
 */
@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_tokens_hash", columnList = "tokenHash"),
                @Index(name = "idx_refresh_tokens_user", columnList = "user_id"),
                @Index(name = "idx_refresh_tokens_expires", columnList = "expiresAt")
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * SHA-256 Hash des Tokens (Base64-encoded, 44 Zeichen).
     * Der Klartext-Token wird nie gespeichert.
     */
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /**
     * User, dem dieser Token gehört.
     * Lazy geladen, da nicht immer benötigt.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Ablaufzeitpunkt des Tokens.
     */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /**
     * Erstellungszeitpunkt.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Letzter Verwendungszeitpunkt.
     * Wird bei jeder Token-Validierung aktualisiert.
     */
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    /**
     * Widerrufsstatus.
     * True wenn Token manuell invalidiert wurde (Logout, Password-Reset).
     */
    @Builder.Default
    @Column(nullable = false)
    private boolean revoked = false;

    /**
     * Optionale Geräteinformationen.
     * Kann User-Agent, IP-Adresse oder andere Identifikationsmerkmale enthalten.
     */
    @Column(name = "device_info", length = 500)
    private String deviceInfo;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        lastUsedAt = LocalDateTime.now();
    }

    /**
     * Prüft ob der Token abgelaufen ist.
     *
     * @return true wenn aktuelles Datum nach expiresAt liegt
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Prüft ob der Token gültig ist.
     *
     * Ein Token ist gültig wenn er weder widerrufen noch abgelaufen ist.
     *
     * @return true wenn Token verwendbar ist
     */
    public boolean isValid() {
        return !revoked && !isExpired();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RefreshToken that = (RefreshToken) o;
        return id != null && Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}