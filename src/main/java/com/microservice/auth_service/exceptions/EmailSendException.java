package com.microservice.auth_service.exceptions;

/**
 * Exception bei Fehlern während des E-Mail-Versands.
 *
 * Wird geworfen wenn eine E-Mail (z.B. Verifizierungs- oder
 * Passwort-Reset-E-Mail) nicht gesendet werden konnte.
 */
public class EmailSendException extends RuntimeException {
    /**
     * Erstellt Exception mit benutzerdefinierter Fehlermeldung.
     *
     * @param message detaillierte Fehlerbeschreibung
     */
    public EmailSendException(String message) {
        super(message);
    }

    /**
     * Erstellt Exception mit Fehlermeldung und Ursache.
     *
     * @param message detaillierte Fehlerbeschreibung
     * @param cause ursprüngliche Exception
     */
    public EmailSendException(String message, Throwable cause) {
        super(message, cause);
    }
}