package com.microservice.auth_service.dto.request;

import lombok.Data;

@Data
public class RefreshTokenRequest {
    private String refreshToken;
}
