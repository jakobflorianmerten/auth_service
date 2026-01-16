package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.InvalidPasswordResetCodeException;
import com.microservice.auth_service.exceptions.PasswordResetCodeExpiredException;
import com.microservice.auth_service.model.PasswordResetToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.PasswordResetTokenRepository;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

/**
 * Service für Passwort-Reset-Codes.
 *
 * Verwaltet den Lebenszyklus von Reset-Codes:
 * - Generierung eines 6-stelligen numerischen Codes
 * - Validierung bei Eingabe durch den Benutzer
 * - Automatisches Löschen abgelaufener Codes
 *
 * Pro Benutzer existiert maximal ein aktiver Code. Bei Neugenerierung
 * werden vorherige Codes gelöscht.
 *
 * Sicherheitshinweise:
 * - Codes werden mit SecureRandom generiert
 * - Codes sind 1 Stunde gültig (kürzer als Verifizierungscodes)
 * - Abgelaufene Codes werden bei Validierung automatisch gelöscht
 *
 * @see PasswordResetToken
 * @see EmailService#sendPasswordResetEmail
 */
@Slf4j
@Service
public class PasswordResetTokenService {

    private static final int CODE_LENGTH = 6;
    private static final int EXPIRATION_HOURS = 1;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final PasswordResetTokenRepository tokenRepository;

    public PasswordResetTokenService(PasswordResetTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    /**
     * Erstellt einen neuen Passwort-Reset-Code für einen Benutzer.
     *
     * Löscht zunächst alle existierenden Codes des Benutzers, um
     * sicherzustellen, dass nur ein aktiver Code existiert.
     *
     * @param user Benutzer, für den der Code erstellt wird
     * @return 6-stelliger numerischer Reset-Code
     */
    @Transactional
    public String createPasswordResetToken(User user) {
        deleteTokensByUser(user);

        String code = generateResetCode();

        PasswordResetToken token = PasswordResetToken.builder()
                .token(code)
                .user(user)
                .expiryDate(LocalDateTime.now().plusHours(EXPIRATION_HOURS))
                .build();

        tokenRepository.save(token);
        log.debug("Password reset token created for user: {}", user.getEmail());

        return code;
    }

    /**
     * Validiert einen Passwort-Reset-Code.
     *
     * Prüft ob der Code existiert und noch nicht abgelaufen ist.
     * Abgelaufene Codes werden automatisch gelöscht.
     *
     * @param code eingegebener Reset-Code
     * @return gültiges PasswordResetToken
     * @throws InvalidPasswordResetCodeException wenn Code nicht existiert
     * @throws PasswordResetCodeExpiredException wenn Code abgelaufen ist
     */
    @Transactional
    public PasswordResetToken validateToken(String code) {
        PasswordResetToken token = tokenRepository.findByToken(code)
                .orElseThrow(InvalidPasswordResetCodeException::new);

        if (token.isExpired()) {
            tokenRepository.delete(token);
            log.debug("Expired password reset token deleted for user: {}", token.getUser().getEmail());
            throw new PasswordResetCodeExpiredException();
        }

        return token;
    }

    /**
     * Löscht alle Reset-Codes eines Benutzers.
     *
     * Wird aufgerufen bei:
     * - Neugenerierung eines Codes
     * - Erfolgreichem Passwort-Reset
     *
     * @param user Benutzer, dessen Codes gelöscht werden
     */
    @Transactional
    public void deleteTokensByUser(User user) {
        tokenRepository.deleteByUser(user);
    }

    /**
     * Löscht einen spezifischen Reset-Code.
     *
     * Wird nach erfolgreichem Passwort-Reset aufgerufen.
     *
     * @param token zu löschender Token
     */
    @Transactional
    public void deleteToken(PasswordResetToken token) {
        tokenRepository.delete(token);
    }

    /**
     * Löscht alle abgelaufenen Reset-Codes.
     *
     * Sollte regelmäßig via Scheduled Task aufgerufen werden,
     * um die Datenbank sauber zu halten.
     */
    @Transactional
    public void deleteExpiredTokens() {
        tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        log.debug("Expired password reset tokens cleaned up");
    }

    /**
     * Generiert einen kryptographisch sicheren 6-stelligen Code.
     *
     * @return numerischer Code als String (z.B. "738291")
     */
    private String generateResetCode() {
        StringBuilder code = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            code.append(SECURE_RANDOM.nextInt(10));
        }
        return code.toString();
    }
}