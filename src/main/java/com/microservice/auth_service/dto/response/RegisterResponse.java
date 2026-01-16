package com.microservice.auth_service.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * Response nach erfolgreicher Registrierung.
 */
@Getter
@Builder
public class RegisterResponse {

    private final String message;
    private final String email;
}