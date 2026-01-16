package com.microservice.auth_service.configuration;
import com.microservice.auth_service.services.UserService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;


/**
 * Zentrale Spring Security Konfiguration für den Authentication Service.
 *
 * Konfiguriert JWT-basierte stateless Authentifizierung, CORS, Endpoint-Autorisierung
 * und Security Headers. CSRF ist deaktiviert, da Tokens im Authorization-Header
 * übertragen werden.
 *
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(CorsProperties.class)
public class SecurityConfig {

    private final UserService userService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CorsProperties corsProperties;

    public SecurityConfig(
            UserService userService,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            CorsProperties corsProperties
    ) {
        this.userService = userService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.corsProperties = corsProperties;
    }

    /**
     * Konfiguriert die Security Filter Chain für alle HTTP-Anfragen.
     *
     * Öffentliche Endpunkte (permitAll):
     * - /register, /login, /refresh, /logout - Authentifizierungs-Flow
     * - /verify-email, /resend-verification-code - E-Mail-Verifizierung
     * - /google - OAuth2 Login via Google
     * - /request-password-reset, /reset-password - Passwort-Reset
     * - /.well-known/** - JWKS-Endpunkt für Public Key Distribution
     * Auf die öffentlichen Endpunkte sollte in Production noch ein Rate-Limiting gesetzt werden,
     * um diese vor Angriffen zu schützen.
     * Der JwtAuthenticationFilter wird vor dem UsernamePasswordAuthenticationFilter
     * ausgeführt und validiert Tokens aus dem Authorization-Header.
     *
     * @param http HttpSecurity Builder
     * @return konfigurierte SecurityFilterChain
     * @throws Exception bei Konfigurationsfehlern
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationProvider authenticationProvider) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentTypeOptions(content -> {})
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/register",
                                "/login",
                                "/refresh",
                                "/verify-email",
                                "/resend-verification-code",
                                "/google",
                                "/request-password-reset",
                                "/reset-password",
                                "/.well-known/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .logout(AbstractHttpConfigurer::disable)
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * CORS-Konfiguration für Cross-Origin Requests von Frontend-Clients.
     *
     * Erlaubte Origins werden aus application.yaml geladen (cors.allowed-origins).
     * Credentials sind erlaubt für Authorization-Header. Preflight-Responses
     * werden 1 Stunde gecached.
     *
     * @return CorsConfigurationSource für alle Pfade
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(corsProperties.getAllowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setExposedHeaders(List.of("X-Rate-Limit-Retry-After-Seconds"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    /**
     * Authentication Provider für datenbankbasierte Authentifizierung.
     *
     * Verwendet UserService zum Laden der Benutzerdaten und BCrypt
     * zum Passwort-Vergleich.
     *
     * @return konfigurierter DaoAuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider(BCryptPasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    /**
     * AuthenticationManager für programmatische Authentifizierung im LoginService.
     * Wird benötigt für: authenticationManager.authenticate(
     *     new UsernamePasswordAuthenticationToken(email, password))
     *
     * @param config AuthenticationConfiguration von Spring Security
     * @return AuthenticationManager
     * @throws Exception bei Konfigurationsfehlern
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}
