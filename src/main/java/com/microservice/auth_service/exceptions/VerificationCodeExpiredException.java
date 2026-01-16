package com.microservice.auth_service.exceptions;

/**
 * Exception bei abgelaufenem E-Mail-Verifizierungscode.
 *
 * Wird geworfen wenn ein Benutzer versucht, einen Verifizierungscode
 * zu verwenden, dessen Gültigkeitsdauer überschritten ist.
 */
public class VerificationCodeExpiredException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public VerificationCodeExpiredException() {
        super("Verification code has expired. Please request a new one");
    }
}