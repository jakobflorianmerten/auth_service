package com.microservice.auth_service.services;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.microservice.auth_service.configuration.GoogleProperties;
import com.microservice.auth_service.exceptions.GoogleEmailNotVerifiedException;
import com.microservice.auth_service.exceptions.InvalidGoogleTokenException;
import com.microservice.auth_service.exceptions.UserAlreadyExistsException;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service für Google OAuth2 Authentifizierung.
 *
 * Validiert Google ID-Tokens, die vom Frontend nach erfolgreichem
 * Google Sign-In übermittelt werden, und verwaltet die User-Erstellung
 * bzw. das Account-Linking.
 *
 * Flow:
 * 1. Frontend führt Google Sign-In durch und erhält ID-Token
 * 2. Frontend sendet ID-Token an /google Endpoint
 * 3. Dieser Service validiert das Token gegen Google's Server
 * 4. Bei gültigem Token: User wird gefunden oder erstellt
 * 5. Auth-Service gibt eigene JWTs zurück
 *
 * Account-Linking (Sicherheitsregeln):
 * - Neuer User: Account wird mit Google erstellt
 * - Existierender User mit Google-Provider: Login erfolgreich
 * - Existierender User ohne Passwort: Account wird mit Google verknüpft
 * - Existierender User mit Passwort: Login wird abgelehnt (Sicherheit)
 *
 * @see GoogleProperties
 */
@Slf4j
@Service
public class GoogleAuthService {

    private static final String PROVIDER_GOOGLE = "google";

    private final UserRepository userRepository;
    private final GoogleIdTokenVerifier verifier;

    /**
     * Konstruktor initialisiert den Google Token Verifier.
     *
     * Der Verifier prüft Tokens gegen Google's öffentliche Schlüssel
     * und validiert die Audience gegen konfigurierte Client-IDs.
     *
     * @param userRepository   Repository für User-Operationen
     * @param googleProperties Konfiguration mit erlaubten Client-IDs
     */
    public GoogleAuthService(UserRepository userRepository, GoogleProperties googleProperties) {
        this.userRepository = userRepository;
        this.verifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(),
                new GsonFactory()
        )
                .setAudience(googleProperties.getClientIds())
                .build();
    }

    /**
     * Authentifiziert einen User mit Google ID-Token.
     *
     * Validiert das Token, extrahiert User-Informationen und erstellt
     * oder aktualisiert den User in der Datenbank.
     *
     * @param idTokenString Google ID-Token vom Frontend
     * @return authentifizierter User
     * @throws InvalidGoogleTokenException      wenn Token ungültig oder Verifikation fehlschlägt
     * @throws GoogleEmailNotVerifiedException  wenn Google-E-Mail nicht verifiziert ist
     * @throws UserAlreadyExistsException       wenn Account mit Passwort existiert (kein Auto-Linking)
     */
    public User authenticateWithGoogle(String idTokenString) {
        GoogleIdToken idToken = verifyToken(idTokenString);
        GoogleIdToken.Payload payload = idToken.getPayload();

        String email = payload.getEmail();
        String googleUserId = payload.getSubject();
        boolean emailVerified = payload.getEmailVerified();

        if (!emailVerified) {
            log.warn("Google authentication failed: email not verified for {}", email);
            throw new GoogleEmailNotVerifiedException();
        }

        User user = findOrCreateUser(email, googleUserId);
        log.info("User authenticated via Google: {}", email);

        return user;
    }

    /**
     * Verifiziert ein Google ID-Token.
     *
     * Prüft:
     * - Token-Signatur gegen Google's öffentliche Schlüssel
     * - Token ist nicht abgelaufen
     * - Audience stimmt mit konfigurierten Client-IDs überein
     *
     * @param idTokenString Token-String vom Frontend
     * @return verifiziertes GoogleIdToken
     * @throws InvalidGoogleTokenException bei ungültigem Token
     */
    private GoogleIdToken verifyToken(String idTokenString) {
        try {
            GoogleIdToken idToken = verifier.verify(idTokenString);

            if (idToken == null) {
                log.warn("Google token verification failed: token is invalid");
                throw new InvalidGoogleTokenException();
            }

            return idToken;
        } catch (InvalidGoogleTokenException e) {
            throw e;
        } catch (Exception e) {
            log.error("Google token verification error: {}", e.getMessage());
            throw new InvalidGoogleTokenException("Failed to verify Google token");
        }
    }

    /**
     * Findet einen existierenden User oder erstellt einen neuen.
     *
     * Sicherheitslogik:
     * - User existiert nicht: Neuen Google-User erstellen
     * - User hat bereits Google-Provider: Login erlauben
     * - User hat kein Passwort: Account mit Google verknüpfen
     * - User hat Passwort: Login ablehnen (Account-Übernahme verhindern)
     *
     * @param email        E-Mail aus Google-Token
     * @param googleUserId Google User-ID (Subject)
     * @return gefundener oder erstellter User
     * @throws UserAlreadyExistsException wenn Account mit Passwort existiert
     */
    private User findOrCreateUser(String email, String googleUserId) {
        return userRepository.findByEmail(email)
                .map(existingUser -> handleExistingUser(existingUser, googleUserId))
                .orElseGet(() -> createGoogleUser(email, googleUserId));
    }

    /**
     * Behandelt Login für existierenden User.
     *
     * @param user         existierender User
     * @param googleUserId Google User-ID
     * @return User wenn Login erlaubt
     * @throws UserAlreadyExistsException wenn Account mit Passwort existiert
     */
    private User handleExistingUser(User user, String googleUserId) {
        // User hat bereits Google-Provider: Login erlauben
        if (PROVIDER_GOOGLE.equals(user.getProvider())) {
            return user;
        }

        // User hat Passwort: Account-Übernahme verhindern
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            log.warn("Google login rejected: account with password exists for {}", user.getEmail());
            throw new UserAlreadyExistsException(
                    "An account with this email already exists. Please login with your password."
            );
        }

        // User hat kein Passwort und keinen Provider: Account verknüpfen
        return linkGoogleAccount(user, googleUserId);
    }

    /**
     * Erstellt einen neuen User mit Google-Authentifizierung.
     *
     * @param email        E-Mail aus Google-Token
     * @param googleUserId Google User-ID
     * @return neu erstellter User
     */
    private User createGoogleUser(String email, String googleUserId) {
        User newUser = User.builder()
                .email(email)
                .provider(PROVIDER_GOOGLE)
                .providerId(googleUserId)
                .enabled(true)
                .emailVerified(true)
                .build();

        User savedUser = userRepository.save(newUser);
        log.info("New user created via Google: {}", email);

        return savedUser;
    }

    /**
     * Verknüpft einen existierenden Account mit Google.
     *
     * Wird nur aufgerufen wenn der User kein Passwort hat,
     * z.B. bei einem unvollständigen Registrierungsprozess.
     *
     * @param user         existierender User ohne Passwort
     * @param googleUserId Google User-ID
     * @return aktualisierter User
     */
    private User linkGoogleAccount(User user, String googleUserId) {
        user.setProvider(PROVIDER_GOOGLE);
        user.setProviderId(googleUserId);
        user.setEmailVerified(true);
        user.setEnabled(true);

        userRepository.save(user);
        log.info("Account without password linked with Google: {}", user.getEmail());

        return user;
    }
}