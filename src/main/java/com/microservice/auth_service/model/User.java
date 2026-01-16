package com.microservice.auth_service.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * User-Entity für Authentifizierung.
 *
 * Implementiert Spring Security's UserDetails für nahtlose Integration
 * mit dem Security-Framework. Unterstützt zwei Registrierungsarten:
 * - Email/Password: password ist gesetzt, provider ist null
 * - OAuth (Google): provider und providerId sind gesetzt, password kann null sein
 *
 * Account-Status:
 * - enabled: Account ist aktiviert (false bis E-Mail verifiziert)
 * - emailVerified: E-Mail-Adresse wurde bestätigt
 *
 * @see org.springframework.security.core.userdetails.UserDetails
 */
@Entity
@Table(
        name = "users",
        indexes = {
                @Index(name = "idx_users_email", columnList = "email")
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * E-Mail-Adresse, dient gleichzeitig als Username für Spring Security.
     */
    @NotBlank
    @Email
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * BCrypt-gehashtes Passwort.
     * Null bei OAuth-only Accounts (z.B. Google-Login).
     */
    @Column(length = 72)
    private String password;

    /**
     * OAuth-Provider Name (z.B. "google").
     * Null bei Email/Password-Registrierung.
     */
    @Column(length = 50)
    private String provider;

    /**
     * User-ID beim OAuth-Provider.
     * Null bei Email/Password-Registrierung.
     */
    @Column(name = "provider_id", length = 255)
    private String providerId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * Account-Aktivierungsstatus.
     * False bis E-Mail verifiziert wurde.
     */
    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = false;

    /**
     * E-Mail-Verifizierungsstatus.
     */
    @Builder.Default
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // === UserDetails Implementation ===

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Gibt die E-Mail als Username zurück.
     *
     * @return E-Mail-Adresse
     */
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    // === equals/hashCode basierend auf ID ===

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id != null && Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}