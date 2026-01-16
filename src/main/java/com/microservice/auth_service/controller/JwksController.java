package com.microservice.auth_service.controller;

import com.microservice.auth_service.services.JwtService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Controller für OAuth2/OIDC Discovery Endpunkte.
 *
 * Stellt den Public Key im JWKS-Format bereit, damit andere Services
 * die JWT-Signatur validieren können, ohne den Auth-Service direkt
 * zu kontaktieren.
 */
@RestController
@RequestMapping("/.well-known")
public class JwksController {

    private final JwtService jwtService;

    public JwksController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * JWKS-Endpunkt (JSON Web Key Set).
     *
     * Gibt den Public Key im standardisierten JWKS-Format zurück.
     * Andere Services können diesen Endpunkt abfragen und den Key
     * für die JWT-Validierung cachen.
     *
     * @return JWKS mit allen aktiven Public Keys
     */
    @GetMapping(value = "/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwks() {
        RSAPublicKey publicKey = (RSAPublicKey) jwtService.getPublicKey();

        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "n", base64UrlEncode(publicKey.getModulus().toByteArray()),
                "e", base64UrlEncode(publicKey.getPublicExponent().toByteArray())
        );

        return Map.of("keys", List.of(jwk));
    }

    /**
     * Base64URL-Encoding ohne Padding (gemäß RFC 7517).
     */
    private String base64UrlEncode(byte[] bytes) {
        // Führende Null-Bytes entfernen (BigInteger fügt diese manchmal hinzu)
        if (bytes.length > 0 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
