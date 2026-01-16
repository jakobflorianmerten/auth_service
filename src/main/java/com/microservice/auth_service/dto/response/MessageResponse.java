package com.microservice.auth_service.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * Response nach erfolgreichem Senden eines Verifizierungscodes.
 */
@Getter
@Builder
public class MessageResponse {

    private final String message;
}