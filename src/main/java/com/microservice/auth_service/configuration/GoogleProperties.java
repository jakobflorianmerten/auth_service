package com.microservice.auth_service.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Konfigurationsklasse für Google OAuth2-Einstellungen aus application.yaml.
 *
 * Bindet Properties unter dem Prefix "google" an diese Klasse. Wird verwendet,
 * um Google ID-Tokens zu validieren, die vom Frontend nach erfolgreichem
 * Google Sign-In übermittelt werden.
 *
 * Beispiel application.yaml:
 *
 *     google:
 *       client-ids:
 *         - 123456789.apps.googleusercontent.com
 *         - 987654321.apps.googleusercontent.com
 *
 * Mehrere Client-IDs werden unterstützt für:
 * - Unterschiedliche Plattformen (Web, Android, iOS)
 *
 * @see com.microservice.auth_service.services.GoogleAuthService
 */
@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "google")
public class GoogleProperties {
    private List<String> clientIds;

}