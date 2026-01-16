package com.microservice.auth_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für die Authentifizierungsantwort.
 * Wird nach erfolgreicher Anmeldung oder Token-Erneuerung zurückgegeben
 * und enthält die JWT-Tokens für die weitere Authentifizierung.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    /**
     * JWT Access-Token für die API-Authentifizierung.
     * Muss bei jedem authentifizierten API-Aufruf im Authorization-Header mitgesendet werden.
     */
    private String accessToken;

    /**
     * Refresh-Token zur Erneuerung des Access-Tokens.
     * Kann verwendet werden, um einen neuen Access-Token zu erhalten, ohne erneute Anmeldung.
     */
    private String refreshToken;

    /**
     * Token-Typ für den Authorization-Header.
     * Standardwert ist "Bearer".
     */
    private String tokenType = "Bearer";

    /**
     * Gültigkeitsdauer des Access-Tokens in Sekunden.
     */
    private Long expiresIn;
}
