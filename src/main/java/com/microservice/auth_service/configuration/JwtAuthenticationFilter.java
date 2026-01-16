package com.microservice.auth_service.configuration;

import com.microservice.auth_service.exceptions.JwtTokenException;
import com.microservice.auth_service.services.JwtService;
import com.microservice.auth_service.services.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

/**
 * JWT-Authentifizierungsfilter für stateless Token-basierte Authentifizierung.
 *
 * Dieser Filter wird bei jeder Anfrage einmal ausgeführt (OncePerRequestFilter) und:
 * - Extrahiert das JWT aus dem Authorization-Header (Bearer Token)
 * - Validiert Token-Signatur und Ablaufzeit über JwtService
 * - Lädt den User aus der Datenbank und setzt den SecurityContext
 *
 * Der Filter ist in der SecurityFilterChain vor dem UsernamePasswordAuthenticationFilter
 * registriert. Bei fehlendem Token wird die Anfrage ohne Authentication weitergeleitet –
 * öffentliche Endpunkte funktionieren weiterhin.
 *
 * Fehlerbehandlung erfolgt über den HandlerExceptionResolver, sodass JWT-Fehler
 * einheitlich über den GlobalExceptionHandler als JSON-Response zurückgegeben werden.
 *
 * @see SecurityConfig
 * @see JwtService
 * @see com.microservice.auth_service.exceptions.GlobalExceptionHandler
 */
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;
    private final HandlerExceptionResolver exceptionResolver;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            UserService userService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        // Wenn kein Authorization Header vorhanden ist, weiter zum nächsten Filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extrahiere JWT Token
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);

            // Wenn User noch nicht authentifiziert ist
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userService.loadUserByUsername(userEmail);

                // Validiere Token
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    log.warn("Invalid JWT token for user: {}", userEmail);
                    exceptionResolver.resolveException(request, response, null,
                            new JwtTokenException("Invalid or expired token"));
                    return;
                }
            }
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            exceptionResolver.resolveException(request, response, null,
                    new JwtTokenException("Token has expired", e));
        } catch (MalformedJwtException | SignatureException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            exceptionResolver.resolveException(request, response, null,
                    new JwtTokenException("Invalid token format", e));
        } catch (Exception e) {
            log.error("JWT authentication error: {}", e.getMessage(), e);
            exceptionResolver.resolveException(request, response, null,
                    new JwtTokenException("Authentication failed", e));
        }
    }
}
