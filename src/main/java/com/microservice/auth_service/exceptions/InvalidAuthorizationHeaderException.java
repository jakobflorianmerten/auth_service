package com.microservice.auth_service.exceptions;

/**
 * Exception bei ungültigem Authorization-Header-Format.
 *
 * Wird geworfen wenn der Authorization-Header nicht dem erwarteten
 * Format "Bearer &lt;token&gt;" entspricht.
 */
public class InvalidAuthorizationHeaderException extends RuntimeException {
    /**
     * Erstellt Exception mit Standard-Fehlermeldung.
     */
    public InvalidAuthorizationHeaderException() {
        super("Invalid authorization header format. Expected: Bearer <token>");
    }
}