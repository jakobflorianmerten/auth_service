package com.microservice.auth_service.repositories;

import com.microservice.auth_service.model.PasswordResetToken;
import com.microservice.auth_service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository für Passwort-Reset-Token.
 *
 * Verwaltet die Persistenz von Tokens, die für das Zurücksetzen
 * von Benutzerpasswörtern verwendet werden.
 */
@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    /**
     * Sucht einen Passwort-Reset-Token anhand seines Wertes.
     *
     * @param token der Token-String
     * @return Optional mit dem gefundenen Token
     */
    Optional<PasswordResetToken> findByToken(String token);

    /**
     * Löscht alle Passwort-Reset-Token eines Benutzers.
     *
     * @param user der Benutzer
     */
    void deleteByUser(User user);

    /**
     * Löscht alle abgelaufenen Token vor dem angegebenen Datum.
     *
     * @param dateTime Stichtag für die Löschung
     */
    void deleteByExpiryDateBefore(LocalDateTime dateTime);
}