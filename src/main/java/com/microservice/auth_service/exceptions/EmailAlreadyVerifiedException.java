package com.microservice.auth_service.exceptions;

/**
 * Exception wenn eine E-Mail-Adresse bereits verifiziert wurde.
 *
 * Wird geworfen wenn ein Benutzer versucht, eine bereits
 * verifizierte E-Mail-Adresse erneut zu verifizieren.
 */
public class EmailAlreadyVerifiedException extends RuntimeException {
    /**
     * Erstellt Exception für bereits verifizierte E-Mail.
     *
     * @param email E-Mail-Adresse die bereits verifiziert wurde
     */
    public EmailAlreadyVerifiedException(String email) {
        super("Email '" + email + "' is already verified");
    }
}
