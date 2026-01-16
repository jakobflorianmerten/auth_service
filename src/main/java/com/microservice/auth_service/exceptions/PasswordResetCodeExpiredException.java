package com.microservice.auth_service.exceptions;

/**
 * Exception bei abgelaufenem Passwort-Reset-Code.
 *
 * Wird geworfen wenn ein Benutzer versucht, einen Passwort-Reset-Code
 * zu verwenden, dessen Gültigkeitsdauer überschritten ist.
 */
public class PasswordResetCodeExpiredException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public PasswordResetCodeExpiredException() {
        super("Password reset code has expired");
    }
}