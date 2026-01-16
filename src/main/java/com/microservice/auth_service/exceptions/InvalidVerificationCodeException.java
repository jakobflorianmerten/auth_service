package com.microservice.auth_service.exceptions;

/**
 * Exception bei ungültigem E-Mail-Verifizierungscode.
 *
 * Wird geworfen wenn ein übermittelter Verifizierungscode nicht
 * mit dem gespeicherten Code übereinstimmt oder nicht existiert.
 */
public class InvalidVerificationCodeException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public InvalidVerificationCodeException() {
        super("Invalid verification code");
    }

    /**
     * Erstellt Exception mit benutzerdefinierter Fehlermeldung.
     *
     * @param message detaillierte Fehlerbeschreibung
     */
    public InvalidVerificationCodeException(String message) {
        super(message);
    }
}