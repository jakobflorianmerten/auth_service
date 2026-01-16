package com.microservice.auth_service.exceptions;

/**
 * Exception bei Fehlern während der RSA-Schlüssel-Initialisierung.
 *
 * Wird geworfen wenn die RSA-Schlüssel für die JWT-Signierung
 * nicht geladen oder initialisiert werden können.
 */
public class RsaKeyInitializationException extends RuntimeException {
    /**
     * Erstellt Exception mit Fehlermeldung und Ursache.
     *
     * @param message detaillierte Fehlerbeschreibung
     * @param cause ursprüngliche Exception
     */
    public RsaKeyInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}