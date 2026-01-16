package com.microservice.auth_service.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Konfigurationsklasse für CORS-Einstellungen aus application.yaml.
 *
 * Bindet Properties unter dem Prefix "cors" an diese Klasse. Wird in
 * SecurityConfig verwendet, um erlaubte Origins für Cross-Origin Requests
 * zu konfigurieren.
 *
 * Beispiel application.yaml:
 *
 *     cors:
 *       allowed-origins:
 *         - https://meine-app.de
 *         - https://admin.meine-app.de
 *
 * Muss über @EnableConfigurationProperties(CorsProperties.class) oder
 * @ConfigurationPropertiesScan aktiviert werden.
 *
 * @see SecurityConfig
 */
@ConfigurationProperties(prefix = "cors")
@Getter
@Setter
public class CorsProperties {

    /**
     * Liste der erlaubten Origins für CORS-Requests.
     *
     * Jeder Eintrag muss eine vollständige URL sein (inkl. Protokoll und ggf. Port),
     * z.B. "https://example.com" oder "http://localhost:3000".
     *
     */
    private List<String> allowedOrigins = new ArrayList<>();

}
