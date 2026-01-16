package com.microservice.auth_service.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Email ist erforderlich")
    @Email(message = "Email muss gültig sein")
    private String email;

    @NotBlank(message = "Passwort ist erforderlich")
    private String password;
}
