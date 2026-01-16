package com.microservice.auth_service.repositories;

import com.microservice.auth_service.model.RefreshToken;
import com.microservice.auth_service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository für Refresh-Token.
 *
 * Verwaltet die Persistenz von Refresh-Tokens, die zur Erneuerung
 * von Access-Tokens ohne erneute Anmeldung verwendet werden.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Sucht einen Refresh-Token anhand seines Hash-Wertes.
     *
     * @param tokenHash SHA-256 Hash des Tokens
     * @return Optional mit dem gefundenen Token
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Findet alle Refresh-Token eines Benutzers.
     *
     * @param user der Benutzer
     * @return Liste aller Token des Benutzers
     */
    List<RefreshToken> findAllByUser(User user);

    /**
     * Löscht alle Refresh-Token eines Benutzers.
     *
     * @param user der Benutzer
     */
    void deleteByUser(User user);

    /**
     * Löscht alle abgelaufenen Token vor dem angegebenen Datum.
     *
     * @param date Stichtag für die Löschung
     */
    int deleteByExpiresAtBefore(LocalDateTime date);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user = :user")
    void revokeAllByUser(@Param("user") User user);
}
