package com.microservice.auth_service.repositories;

import com.microservice.auth_service.model.EmailVerificationToken;
import com.microservice.auth_service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository für E-Mail-Verifizierungs-Token.
 *
 * Verwaltet die Persistenz von Tokens, die zur Bestätigung
 * von Benutzer-E-Mail-Adressen verwendet werden.
 */
@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    /**
     * Sucht einen Verifizierungs-Token anhand seines Wertes.
     *
     * @param token der Token-String
     * @return Optional mit dem gefundenen Token
     */
    Optional<EmailVerificationToken> findByToken(String token);

    /**
     * Löscht alle Verifizierungs-Token eines Benutzers.
     *
     * @param user der Benutzer
     */
    void deleteByUser(User user);

    /**
     * Löscht alle abgelaufenen Token vor dem angegebenen Datum.
     *
     * @param date Stichtag für die Löschung
     */
    void deleteByExpiryDateBefore(LocalDateTime date);
}
