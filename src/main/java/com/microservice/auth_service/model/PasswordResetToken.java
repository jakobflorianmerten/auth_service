package com.microservice.auth_service.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Entity für Passwort-Reset-Codes.
 *
 * Speichert 6-stellige numerische Codes, die per E-Mail an den User
 * gesendet werden. Codes sind 1 Stunde gültig.
 *
 * Lebenszyklus:
 * 1. User fordert Passwort-Reset an
 * 2. Code wird generiert und per E-Mail gesendet
 * 3. User gibt Code ein, Passwort wird zurückgesetzt
 * 4. Code wird gelöscht (oder läuft ab)
 *
 * Pro User existiert maximal ein aktiver Code. Bei Neugenerierung
 * werden vorherige Codes gelöscht.
 *
 * @see com.microservice.auth_service.services.PasswordResetTokenService
 */
@Entity
@Table(
        name = "password_reset_tokens",
        indexes = {
                @Index(name = "idx_password_reset_token", columnList = "token"),
                @Index(name = "idx_password_reset_user", columnList = "user_id"),
                @Index(name = "idx_password_reset_expiry", columnList = "expiry_date")
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 6-stelliger numerischer Reset-Code.
     */
    @Column(nullable = false, unique = true, length = 6)
    private String token;

    /**
     * User, für den der Reset-Code erstellt wurde.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Ablaufzeitpunkt des Codes (1 Stunde nach Erstellung).
     */
    @Column(name = "expiry_date", nullable = false)
    private LocalDateTime expiryDate;

    /**
     * Erstellungszeitpunkt.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    /**
     * Prüft ob der Code abgelaufen ist.
     *
     * @return true wenn aktuelles Datum nach expiryDate liegt
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PasswordResetToken that = (PasswordResetToken) o;
        return id != null && Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}