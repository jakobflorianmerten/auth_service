package com.microservice.auth_service.exceptions;

/**
 * Exception wenn ein Benutzer nicht gefunden wurde.
 *
 * Wird geworfen wenn eine Operation einen Benutzer erfordert,
 * der mit der angegebenen E-Mail-Adresse nicht existiert.
 */
public class UserNotFoundException extends RuntimeException {
    /**
     * Erstellt Exception für nicht gefundenen Benutzer.
     *
     * @param email E-Mail-Adresse des gesuchten Benutzers
     */
    public UserNotFoundException(String email) {
        super("User not found with email: " + email);
    }
}