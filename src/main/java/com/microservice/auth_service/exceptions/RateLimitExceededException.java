package com.microservice.auth_service.exceptions;

/**
 * Exception bei Überschreitung des Rate-Limits.
 *
 * Wird geworfen wenn ein Client zu viele Anfragen in einem
 * bestimmten Zeitraum an einen Endpoint sendet.
 */
public class RateLimitExceededException extends RuntimeException {
    /**
     * Erstellt Exception für überschrittenes Rate-Limit.
     *
     * @param endpoint der betroffene Endpoint
     */
    public RateLimitExceededException(String endpoint) {
        super("Rate limit exceeded for endpoint: " + endpoint + ". Please try again later.");
    }

    /**
     * Erstellt Exception mit Wartezeit-Information.
     *
     * @param endpoint der betroffene Endpoint
     * @param retryAfterSeconds Sekunden bis zur nächsten erlaubten Anfrage
     */
    public RateLimitExceededException(String endpoint, long retryAfterSeconds) {
        super("Rate limit exceeded for endpoint: " + endpoint + ". Please try again after " + retryAfterSeconds + " seconds.");
    }
}