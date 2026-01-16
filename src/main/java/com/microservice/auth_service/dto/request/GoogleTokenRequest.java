package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class GoogleTokenRequest {

    @NotBlank(message = "ID token is required")
    private String idToken;
}
