package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.JwtTokenException;
import com.microservice.auth_service.exceptions.RsaKeyInitializationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

/**
 * Service für JWT-Operationen: Generierung, Validierung und Claim-Extraktion.
 *
 * Verwendet RSA-256 für Token-Signierung. Der Private Key signiert Tokens,
 * der Public Key wird über den JWKS-Endpunkt bereitgestellt, damit andere
 * Services Tokens validieren können.
 *
 * Konfiguration via application.yaml:
 * - jwt.private-key: RSA Private Key im PEM-Format
 * - jwt.public-key: RSA Public Key im PEM-Format
 * - jwt.access-token-expiration: Gültigkeit in Millisekunden
 * - app.issuer: Issuer-URL für JWT (z.B. https://auth.example.com)
 *
 * @see com.microservice.auth_service.controller.JwksController
 * @see RefreshTokenService
 */
@Service
public class JwtService {

    @Value("${jwt.private-key}")
    private String rsaPrivateKeyPem;

    @Value("${jwt.public-key}")
    private String rsaPublicKeyPem;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${app.issuer}")
    private String issuer;

    private PrivateKey privateKey;
    /**
     * -- GETTER --
     *  Gibt den Public Key für den JWKS-Endpunkt zurück.
     *
     * @return RSA Public Key
     */
    @Getter
    private PublicKey publicKey;

    /**
     * Initialisiert die RSA-Schlüssel beim Application-Start.
     *
     * Bei fehlerhafter Key-Konfiguration schlägt der Start fehl.
     *
     * @throws RsaKeyInitializationException wenn Keys nicht geladen werden können
     */
    @PostConstruct
    private void initializeKeys() {
        try {
            if (rsaPrivateKeyPem == null || rsaPrivateKeyPem.isEmpty()) {
                throw new IllegalStateException("RSA private key not configured");
            }
            if (rsaPublicKeyPem == null || rsaPublicKeyPem.isEmpty()) {
                throw new IllegalStateException("RSA public key not configured");
            }

            privateKey = loadPrivateKey(rsaPrivateKeyPem);
            publicKey = loadPublicKey(rsaPublicKeyPem);
        } catch (Exception e) {
            throw new RsaKeyInitializationException("Failed to initialize RSA keys", e);
        }
    }

    /**
     * Generiert einen Access Token für API-Authentifizierung.
     *
     * @param userDetails Spring Security UserDetails (Username wird als Subject verwendet)
     * @return signierter JWT-String
     */
    public String generateAccessToken(UserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuer(issuer)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(privateKey)
                .compact();
    }

    /**
     * Generiert einen Refresh Token als JWT.
     *
     * Der Refresh Token wird mit denselben RSA-Schlüsseln signiert wie der Access Token,
     * hat aber eine längere Gültigkeitsdauer.
     *
     * @param userDetails Spring Security UserDetails (Username wird als Subject verwendet)
     * @return signierter JWT-String
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuer(issuer)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(privateKey)
                .compact();
    }

    /**
     * Extrahiert den Username (E-Mail) aus einem Token.
     *
     * @param token JWT-String
     * @return Username aus dem Subject-Claim
     * @throws JwtTokenException bei ungültigem Token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrahiert einen beliebigen Claim aus dem Token.
     *
     * @param token          JWT-String
     * @param claimsResolver Funktion zur Claim-Extraktion
     * @return extrahierter Claim-Wert
     * @throws JwtTokenException bei ungültigem Token
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Validiert ein Token gegen UserDetails.
     *
     * Prüft ob Username übereinstimmt und Token nicht abgelaufen ist.
     * Signaturprüfung erfolgt implizit in extractAllClaims().
     *
     * @param token       JWT-String
     * @param userDetails UserDetails zum Abgleich
     * @return true wenn Token gültig
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Validiert einen Refresh Token (JWT-Signatur und Ablaufdatum).
     *
     * Prüft nur die kryptographische Signatur und das Ablaufdatum,
     * ohne UserDetails-Abgleich. Die DB-Validierung erfolgt separat
     * im RefreshTokenService.
     *
     * @param token JWT-String
     * @return true wenn Signatur gültig und Token nicht abgelaufen
     */
    public boolean isRefreshTokenValid(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Prüft ob ein Token abgelaufen ist.
     *
     * @param token JWT-String
     * @return true wenn Expiration-Datum in der Vergangenheit liegt
     * @throws JwtTokenException bei ungültigem Token
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extrahiert das Ablaufdatum aus einem Token.
     *
     * @param token JWT-String
     * @return Expiration-Datum
     * @throws JwtTokenException bei ungültigem Token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrahiert und validiert alle Claims aus einem Token.
     *
     * Verifiziert die RSA-Signatur mit dem Public Key. Bei ungültiger
     * Signatur oder abgelaufenem Token wird eine Exception geworfen.
     *
     * @param token JWT-String
     * @return Claims-Objekt mit allen Token-Claims
     * @throws JwtTokenException bei ungültigem oder abgelaufenem Token
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtTokenException("Failed to parse JWT token", e);
        }
    }

    /**
     * Lädt einen RSA Private Key aus PEM-Format.
     *
     * Erwartet PKCS#8-Format:
     * -----BEGIN PRIVATE KEY-----
     * [Base64-encoded key]
     * -----END PRIVATE KEY-----
     *
     * @param pem Private Key im PEM-Format
     * @return PrivateKey-Objekt
     * @throws Exception bei ungültigem Format oder Parsing-Fehlern
     */
    private PrivateKey loadPrivateKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * Lädt einen RSA Public Key aus PEM-Format.
     *
     * Erwartet X.509-Format:
     * -----BEGIN PUBLIC KEY-----
     * [Base64-encoded key]
     * -----END PUBLIC KEY-----
     *
     * @param pem Public Key im PEM-Format
     * @return PublicKey-Objekt
     * @throws Exception bei ungültigem Format oder Parsing-Fehlern
     */
    private PublicKey loadPublicKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}