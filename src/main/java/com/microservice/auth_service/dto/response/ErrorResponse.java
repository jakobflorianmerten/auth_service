package com.microservice.auth_service.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * DTO für Fehlerantworten.
 * Standardisiertes Format für alle Fehlermeldungen der API.
 * Enthält Details zum Fehler sowie optional eine Liste von Feldfehlern bei Validierungsproblemen.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    /**
     * Zeitstempel des Fehlers.
     */
    private Instant timestamp;

    /**
     * HTTP-Statuscode des Fehlers.
     */
    private int status;

    /**
     * Kurze Fehlerbeschreibung (z.B. "Bad Request", "Unauthorized").
     */
    private String error;

    /**
     * Detaillierte Fehlermeldung.
     */
    private String message;

    /**
     * API-Pfad, bei dem der Fehler aufgetreten ist.
     */
    private String path;

    /**
     * Liste der Feldfehler bei Validierungsproblemen.
     * Nur vorhanden, wenn einzelne Felder ungültige Werte enthalten.
     */
    private List<FieldError> fieldErrors;

    /**
     * Repräsentiert einen Validierungsfehler für ein einzelnes Feld.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FieldError {

        /**
         * Name des Feldes mit dem Validierungsfehler.
         */
        private String field;

        /**
         * Fehlermeldung für das betroffene Feld.
         */
        private String message;
    }
}
