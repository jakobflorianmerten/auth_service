package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.InvalidVerificationCodeException;
import com.microservice.auth_service.exceptions.VerificationCodeExpiredException;
import com.microservice.auth_service.model.EmailVerificationToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.EmailVerificationTokenRepository;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

/**
 * Service für E-Mail-Verifizierungscodes nach der Registrierung.
 *
 * Verwaltet den Lebenszyklus von Verifizierungscodes:
 * - Generierung eines 6-stelligen numerischen Codes
 * - Validierung bei Eingabe durch den Benutzer
 * - Automatisches Löschen abgelaufener Codes
 *
 * Pro Benutzer existiert maximal ein aktiver Code. Bei Neugenerierung
 * werden vorherige Codes gelöscht.
 *
 * Sicherheitshinweise:
 * - Codes werden mit SecureRandom generiert
 * - Codes sind 24 Stunden gültig
 * - Abgelaufene Codes werden bei Validierung automatisch gelöscht
 *
 * @see EmailVerificationToken
 * @see EmailService
 */
@Slf4j
@Service
public class EmailVerificationTokenService {

    private static final int CODE_LENGTH = 6;
    private static final int EXPIRATION_HOURS = 24;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final EmailVerificationTokenRepository tokenRepository;

    public EmailVerificationTokenService(EmailVerificationTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    /**
     * Erstellt einen neuen Verifizierungscode für einen Benutzer.
     *
     * Löscht zunächst alle existierenden Codes des Benutzers, um
     * sicherzustellen, dass nur ein aktiver Code existiert.
     *
     * @param user Benutzer, für den der Code erstellt wird
     * @return 6-stelliger numerischer Verifizierungscode
     */
    @Transactional
    public String createVerificationToken(User user) {
        deleteTokensByUser(user);

        String code = generateVerificationCode();

        EmailVerificationToken token = EmailVerificationToken.builder()
                .token(code)
                .user(user)
                .expiryDate(LocalDateTime.now().plusHours(EXPIRATION_HOURS))
                .build();

        tokenRepository.save(token);
        log.debug("Verification token created for user: {}", user.getEmail());

        return code;
    }

    /**
     * Validiert einen Verifizierungscode.
     *
     * Prüft ob der Code existiert und noch nicht abgelaufen ist.
     * Abgelaufene Codes werden automatisch gelöscht.
     *
     * @param code eingegebener Verifizierungscode
     * @return gültiges EmailVerificationToken
     * @throws InvalidVerificationCodeException wenn Code nicht existiert
     * @throws VerificationCodeExpiredException wenn Code abgelaufen ist
     */
    @Transactional
    public EmailVerificationToken validateToken(String code) {
        EmailVerificationToken token = tokenRepository.findByToken(code)
                .orElseThrow(InvalidVerificationCodeException::new);

        if (token.isExpired()) {
            tokenRepository.delete(token);
            log.debug("Expired verification token deleted for user: {}", token.getUser().getEmail());
            throw new VerificationCodeExpiredException();
        }

        return token;
    }

    /**
     * Löscht alle Verifizierungscodes eines Benutzers.
     *
     * Wird aufgerufen bei:
     * - Neugenerierung eines Codes
     * - Erfolgreicher Verifizierung
     *
     * @param user Benutzer, dessen Codes gelöscht werden
     */
    @Transactional
    public void deleteTokensByUser(User user) {
        tokenRepository.deleteByUser(user);
    }

    /**
     * Löscht einen spezifischen Verifizierungscode.
     *
     * Wird nach erfolgreicher Verifizierung aufgerufen.
     *
     * @param token zu löschender Token
     */
    @Transactional
    public void deleteToken(EmailVerificationToken token) {
        tokenRepository.delete(token);
    }

    /**
     * Löscht alle abgelaufenen Verifizierungscodes.
     *
     * Sollte regelmäßig via Scheduled Task aufgerufen werden,
     * um die Datenbank sauber zu halten.
     */
    @Transactional
    public void deleteExpiredTokens() {
        tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        log.debug("Expired verification tokens cleaned up");
    }

    /**
     * Generiert einen kryptographisch sicheren 6-stelligen Code.
     *
     * @return numerischer Code als String (z.B. "042817")
     */
    private String generateVerificationCode() {
        StringBuilder code = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            code.append(SECURE_RANDOM.nextInt(10));
        }
        return code.toString();
    }
}