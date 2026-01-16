package com.microservice.auth_service.exceptions;

/**
 * Exception bei ungültigem Google ID-Token.
 *
 * Wird geworfen wenn die Validierung eines Google ID-Tokens fehlschlägt,
 * z.B. bei abgelaufenem, manipuliertem oder falsch signiertem Token.
 */
public class InvalidGoogleTokenException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public InvalidGoogleTokenException() {
        super("Invalid Google ID token");
    }

    /**
     * Erstellt Exception mit benutzerdefinierter Fehlermeldung.
     *
     * @param message detaillierte Fehlerbeschreibung
     */
    public InvalidGoogleTokenException(String message) {
        super(message);
    }
}