package com.microservice.auth_service.exceptions;

import com.microservice.auth_service.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;

/**
 * Zentrale Exception-Handling-Klasse für den gesamten Auth-Service.
 *
 * Fängt alle Exceptions aus Controllern und dem JwtAuthenticationFilter ab und
 * wandelt sie in einheitliche JSON-Fehlerantworten (ErrorResponse) um.
 *
 * Die Klasse kategorisiert Exceptions nach HTTP-Statuscodes:
 * - 400 Bad Request: Ungültige Eingaben, Token-Format-Fehler
 * - 401 Unauthorized: JWT-Authentifizierungsfehler
 * - 404 Not Found: Ressource nicht gefunden
 * - 409 Conflict: Ressourcenkonflikt (z.B. User existiert bereits)
 * - 410 Gone: Abgelaufene Ressourcen (Verifizierungscodes)
 * - 429 Too Many Requests: Rate-Limiting
 * - 500 Internal Server Error: Unerwartete Serverfehler
 *
 * Sicherheitshinweis: Bei 500-Fehlern werden keine internen Details an den
 * Client zurückgegeben, um Information Disclosure zu vermeiden.
 *
 * @see ErrorResponse
 * @see com.microservice.auth_service.configuration.JwtAuthenticationFilter
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Behandelt Bad-Request-Exceptions (400) für ungültige Benutzereingaben.
     *
     * Abgedeckte Szenarien:
     * - Ungültiger Verifizierungscode bei E-Mail-Bestätigung
     * - Ungültiger Passwort-Reset-Code
     * - Ungültiges Refresh-Token-Format
     * - Fehlerhafter Authorization-Header
     * - Ungültiges Google ID-Token
     * - Nicht verifizierte Google-E-Mail
     * - E-Mail bereits verifiziert
     *
     * @param ex      die geworfene Exception
     * @param request HTTP-Request für Pfad-Information im Log
     * @return ErrorResponse mit Status 400
     */
    @ExceptionHandler({
            InvalidVerificationCodeException.class,
            InvalidPasswordResetCodeException.class,
            InvalidRefreshTokenException.class,
            InvalidAuthorizationHeaderException.class,
            InvalidGoogleTokenException.class,
            GoogleEmailNotVerifiedException.class,
            EmailAlreadyVerifiedException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequestExceptions(RuntimeException ex, HttpServletRequest request) {
        log.warn("Bad request at {}: {}", request.getRequestURI(), ex.getMessage());
        return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    /**
     * Behandelt JWT-Authentifizierungsfehler (401 Unauthorized).
     *
     * Wird ausgelöst bei:
     * - Abgelaufenem JWT
     * - Ungültiger JWT-Signatur
     * - Manipuliertem Token
     *
     * Diese Exception kommt primär vom JwtAuthenticationFilter über den
     * HandlerExceptionResolver.
     *
     * @param ex      JwtTokenException mit Fehlerdetails
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 401
     */
    @ExceptionHandler(JwtTokenException.class)
    public ResponseEntity<ErrorResponse> handleJwtTokenException(JwtTokenException ex, HttpServletRequest request) {
        log.warn("Unauthorized access at {}: {}", request.getRequestURI(), ex.getMessage());
        return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    /**
     * Behandelt User-Not-Found-Fehler (404 Not Found).
     *
     * Wird ausgelöst wenn ein User per E-Mail oder ID nicht gefunden wird,
     * z.B. beim Login, Passwort-Reset oder Token-Refresh.
     *
     * @param ex      UserNotFoundException mit gesuchtem Identifier
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 404
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(UserNotFoundException ex, HttpServletRequest request) {
        log.warn("User not found at {}: {}", request.getRequestURI(), ex.getMessage());
        return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    /**
     * Behandelt Konflikt-Fehler (409 Conflict).
     *
     * Wird ausgelöst wenn ein User mit der angegebenen E-Mail bereits existiert,
     * typischerweise bei der Registrierung.
     *
     * @param ex      UserAlreadyExistsException mit E-Mail-Adresse
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 409
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExistsException(UserAlreadyExistsException ex, HttpServletRequest request) {
        log.warn("Conflict at {}: {}", request.getRequestURI(), ex.getMessage());
        return buildResponse(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    /**
     * Behandelt abgelaufene Ressourcen (410 Gone).
     *
     * Abgedeckte Szenarien:
     * - Verifizierungscode abgelaufen (E-Mail-Bestätigung)
     * - Passwort-Reset-Code abgelaufen
     *
     * 410 Gone signalisiert dem Client, dass die Ressource existierte,
     * aber nicht mehr verfügbar ist und ein neuer Code angefordert werden muss.
     *
     * @param ex      die geworfene Exception
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 410
     */
    @ExceptionHandler({
            VerificationCodeExpiredException.class,
            PasswordResetCodeExpiredException.class
    })
    public ResponseEntity<ErrorResponse> handleGoneExceptions(RuntimeException ex, HttpServletRequest request) {
        log.warn("Resource expired at {}: {}", request.getRequestURI(), ex.getMessage());
        return buildResponse(HttpStatus.GONE, ex.getMessage(), request);
    }

    /**
     * Behandelt Rate-Limiting-Fehler (429 Too Many Requests).
     *
     * Abgedeckte Szenarien:
     * - Zu viele fehlgeschlagene Login-Versuche (Account-Schutz)
     * - Allgemeines Rate-Limit überschritten (API-Schutz)
     *
     * Der Client sollte nach einer Wartezeit erneut versuchen.
     * Die Wartezeit kann im X-Rate-Limit-Retry-After-Seconds Header
     * übermittelt werden (falls implementiert).
     *
     * @param ex      die geworfene Exception
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 429
     */
    @ExceptionHandler({
            RateLimitExceededException.class
    })
    public ResponseEntity<ErrorResponse> handleTooManyRequestsExceptions(RuntimeException ex, HttpServletRequest request) {
        log.warn("Rate limit exceeded at {}: {}", request.getRequestURI(), ex.getMessage());
        return buildResponse(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage(), request);
    }

    /**
     * Behandelt bekannte interne Serverfehler (500 Internal Server Error).
     *
     * Abgedeckte Szenarien:
     * - RSA-Key-Initialisierung fehlgeschlagen (kritischer Startup-Fehler)
     * - E-Mail-Versand fehlgeschlagen
     *
     * Sicherheit: Die tatsächliche Fehlermeldung wird nur geloggt, nicht an
     * den Client zurückgegeben, um Information Disclosure zu vermeiden.
     *
     * @param ex      die geworfene Exception
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 500 und generischer Nachricht
     */
    @ExceptionHandler({
            RsaKeyInitializationException.class,
            EmailSendException.class
    })
    public ResponseEntity<ErrorResponse> handleInternalServerExceptions(RuntimeException ex, HttpServletRequest request) {
        log.error("Internal server error at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An internal error occurred", request);
    }

    /**
     * Behandelt Bean-Validation-Fehler (400 Bad Request).
     *
     * Wird ausgelöst wenn @Valid-annotierte Request-Bodies gegen
     * Validierungsregeln verstoßen (z.B. @NotBlank, @Email, @Size).
     *
     * Im Gegensatz zu anderen 400-Fehlern enthält die Response eine Liste
     * der fehlerhaften Felder mit spezifischen Fehlermeldungen.
     *
     * @param ex      MethodArgumentNotValidException mit Validierungsfehlern
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 400 und fieldErrors-Liste
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        log.warn("Validation failed at {}: {}", request.getRequestURI(), ex.getMessage());

        List<ErrorResponse.FieldError> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> ErrorResponse.FieldError.builder()
                        .field(error.getField())
                        .message(error.getDefaultMessage())
                        .build())
                .toList();

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
                .message("Validation failed")
                .path(request.getRequestURI())
                .fieldErrors(fieldErrors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    /**
     * Fallback-Handler für alle unerwarteten Exceptions (500 Internal Server Error).
     *
     * Fängt alle Exceptions ab, die nicht von spezifischeren Handlern
     * behandelt werden. Dies stellt sicher, dass der Client immer eine
     * strukturierte JSON-Antwort erhält, niemals einen Stack-Trace.
     *
     * Sicherheit: Stack-Trace wird nur geloggt, nicht an den Client gesendet.
     *
     * @param ex      die unerwartete Exception
     * @param request HTTP-Request für Pfad-Information
     * @return ErrorResponse mit Status 500 und generischer Nachricht
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, HttpServletRequest request) {
        log.error("Unexpected error at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", request);
    }


    /**
     * Erstellt eine standardisierte ErrorResponse.
     *
     * @param status  HTTP-Statuscode
     * @param message Fehlermeldung für den Client
     * @param request HTTP-Request für Pfad-Information
     * @return ResponseEntity mit ErrorResponse-Body
     */
    private ResponseEntity<ErrorResponse> buildResponse(HttpStatus status, String message, HttpServletRequest request) {
        ErrorResponse response = ErrorResponse.builder()
                .timestamp(Instant.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(status).body(response);
    }
}
