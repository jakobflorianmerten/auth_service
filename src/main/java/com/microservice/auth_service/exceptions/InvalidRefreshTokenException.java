package com.microservice.auth_service.exceptions;

/**
 * Exception bei ungültigem oder abgelaufenem Refresh-Token.
 *
 * Wird geworfen wenn ein Client versucht, mit einem ungültigen,
 * abgelaufenen oder widerrufenen Refresh-Token ein neues Access-Token
 * zu erhalten.
 */
public class InvalidRefreshTokenException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public InvalidRefreshTokenException() {
        super("Invalid or expired refresh token");
    }

    /**
     * Erstellt Exception mit benutzerdefinierter Fehlermeldung.
     *
     * @param message detaillierte Fehlerbeschreibung
     */
    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}