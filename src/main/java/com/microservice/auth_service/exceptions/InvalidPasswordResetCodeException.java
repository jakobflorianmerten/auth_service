package com.microservice.auth_service.exceptions;

/**
 * Exception bei ungültigem Passwort-Reset-Code.
 *
 * Wird geworfen wenn ein übermittelter Passwort-Reset-Code nicht
 * mit dem gespeicherten Code übereinstimmt oder nicht existiert.
 */
public class InvalidPasswordResetCodeException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public InvalidPasswordResetCodeException() {
        super("Invalid password reset code");
    }
}