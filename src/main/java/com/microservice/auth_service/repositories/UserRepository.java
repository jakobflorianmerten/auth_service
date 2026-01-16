package com.microservice.auth_service.repositories;

import com.microservice.auth_service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Repository für Benutzer-Entitäten.
 *
 * Verwaltet die Persistenz von Benutzerdaten und bietet
 * Methoden zur Suche nach E-Mail-Adresse.
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Sucht einen Benutzer anhand seiner E-Mail-Adresse.
     *
     * @param email die E-Mail-Adresse
     * @return Optional mit dem gefundenen Benutzer
     */
    Optional<User> findByEmail(String email);

    /**
     * Prüft ob ein Benutzer mit der E-Mail-Adresse existiert.
     *
     * @param email die E-Mail-Adresse
     * @return true wenn Benutzer existiert
     */
    boolean existsByEmail(String email);
}
