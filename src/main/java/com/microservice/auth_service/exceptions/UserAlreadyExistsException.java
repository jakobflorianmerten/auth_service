package com.microservice.auth_service.exceptions;

/**
 * Exception wenn ein Benutzer bereits existiert.
 *
 * Wird geworfen wenn bei der Registrierung bereits ein Benutzer
 * mit der angegebenen E-Mail-Adresse existiert.
 */
public class UserAlreadyExistsException extends RuntimeException {
    /**
     * Erstellt Exception für bereits existierenden Benutzer.
     *
     * @param email E-Mail-Adresse des bereits registrierten Benutzers
     */
    public UserAlreadyExistsException(String email) {
        super("User with email '" + email + "' already exists");
    }
}