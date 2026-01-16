package com.microservice.auth_service.exceptions;

/**
 * Exception bei JWT-Token-Verarbeitungsfehlern.
 *
 * Wird geworfen bei Fehlern während der JWT-Erstellung, -Validierung
 * oder -Verarbeitung, z.B. bei ungültiger Signatur oder fehlenden Claims.
 */
public class JwtTokenException extends RuntimeException {
    /**
     * Erstellt Exception mit benutzerdefinierter Fehlermeldung.
     *
     * @param message detaillierte Fehlerbeschreibung
     */
    public JwtTokenException(String message) {
        super(message);
    }

    /**
     * Erstellt Exception mit Fehlermeldung und Ursache.
     *
     * @param message detaillierte Fehlerbeschreibung
     * @param cause ursprüngliche Exception
     */
    public JwtTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}