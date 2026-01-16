package com.microservice.auth_service.dto.request;

import lombok.Data;

/**
 * DTO für die Token-Erneuerung.
 * Enthält den Refresh-Token zur Ausstellung eines neuen Access-Tokens.
 */
@Data
public class RefreshTokenRequest {

    /**
     * Refresh-Token zur Erneuerung des Access-Tokens.
     * Muss ein gültiger, nicht abgelaufener Refresh-Token sein.
     */
    private String refreshToken;
}
