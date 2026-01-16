package com.microservice.auth_service.exceptions;

/**
 * Exception bei nicht verifizierter Google-E-Mail-Adresse.
 *
 * Wird geworfen wenn ein Benutzer versucht, sich mit einem Google-Konto
 * anzumelden, dessen E-Mail-Adresse bei Google nicht verifiziert ist.
 */
public class GoogleEmailNotVerifiedException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public GoogleEmailNotVerifiedException() {
        super("Google email is not verified");
    }
}