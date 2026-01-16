package com.microservice.auth_service.services;

import com.microservice.auth_service.dto.request.RegisterRequest;
import com.microservice.auth_service.dto.response.AuthResponse;
import com.microservice.auth_service.exceptions.EmailAlreadyVerifiedException;
import com.microservice.auth_service.exceptions.UserAlreadyExistsException;
import com.microservice.auth_service.exceptions.UserNotFoundException;
import com.microservice.auth_service.model.PasswordResetToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service für User-Verwaltung und Authentifizierungs-Flows.
 *
 * Implementiert UserDetailsService für Spring Security Integration
 * und stellt folgende Funktionalitäten bereit:
 * - User-Registrierung mit E-Mail-Verifizierung
 * - E-Mail-Verifizierung mit Auto-Login
 * - Passwort-Reset-Flow
 *
 * Sicherheitshinweise:
 * - Passwörter werden mit BCrypt gehasht
 * - Password-Reset gibt keinen Hinweis, ob E-Mail existiert (User-Enumeration-Schutz)
 * - Nach Password-Reset werden alle Refresh-Tokens invalidiert
 *
 * @see JwtService
 * @see RefreshTokenService
 * @see EmailVerificationTokenService
 */
@Slf4j
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final EmailVerificationTokenService verificationTokenService;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetTokenService passwordResetTokenService;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    public UserService(
            UserRepository userRepository,
            BCryptPasswordEncoder passwordEncoder,
            EmailVerificationTokenService verificationTokenService,
            EmailService emailService,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            PasswordResetTokenService passwordResetTokenService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.verificationTokenService = verificationTokenService;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.passwordResetTokenService = passwordResetTokenService;
    }

    /**
     * Lädt einen User anhand seiner E-Mail für Spring Security.
     *
     * @param username E-Mail-Adresse des Users
     * @return UserDetails für Authentifizierung
     * @throws UsernameNotFoundException wenn User nicht existiert
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));
    }

    /**
     * Registriert einen neuen User.
     *
     * Erstellt einen deaktivierten User-Account und sendet eine
     * Verifizierungs-E-Mail. Der Account wird erst nach erfolgreicher
     * E-Mail-Verifizierung aktiviert.
     *
     * @param request Registrierungsdaten (E-Mail, Passwort)
     * @return erstellter User (noch nicht aktiviert)
     * @throws UserAlreadyExistsException wenn E-Mail bereits registriert
     */
    @Transactional
    public User registerUser(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed: email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException(request.getEmail());
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(false)
                .emailVerified(false)
                .build();

        User savedUser = userRepository.save(user);

        String verificationCode = verificationTokenService.createVerificationToken(savedUser);
        emailService.sendVerificationEmail(savedUser.getEmail(), verificationCode);

        log.info("User registered: {}", savedUser.getEmail());
        return savedUser;
    }

    /**
     * Verifiziert eine E-Mail-Adresse und aktiviert den Account.
     *
     * Nach erfolgreicher Verifizierung wird der User automatisch
     * eingeloggt und erhält Access- und Refresh-Tokens.
     *
     * @param code Verifizierungscode aus der E-Mail
     * @return AuthResponse mit Tokens für Auto-Login
     * @throws com.microservice.auth_service.exceptions.InvalidVerificationCodeException wenn Code ungültig
     * @throws com.microservice.auth_service.exceptions.VerificationCodeExpiredException wenn Code abgelaufen
     */
    @Transactional
    public AuthResponse verifyEmail(String code) {
        var token = verificationTokenService.validateToken(code);
        User user = token.getUser();

        user.setEmailVerified(true);
        user.setEnabled(true);
        User verifiedUser = userRepository.save(user);

        verificationTokenService.deleteToken(token);

        String accessToken = jwtService.generateAccessToken(verifiedUser);
        String refreshToken = refreshTokenService.createRefreshToken(verifiedUser, null);

        log.info("Email verified for user: {}", verifiedUser.getEmail());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(accessTokenExpiration / 1000)
                .build();
    }

    /**
     * Sendet den Verifizierungscode erneut.
     *
     * Generiert einen neuen Code und sendet ihn an die E-Mail-Adresse.
     * Der alte Code wird dabei ungültig.
     *
     * @param email E-Mail-Adresse des Users
     * @throws UserNotFoundException wenn User nicht existiert
     * @throws EmailAlreadyVerifiedException wenn E-Mail bereits verifiziert
     */
    @Transactional
    public void resendVerificationCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("Resend verification failed: user not found: {}", email);
                    return new UserNotFoundException(email);
                });

        if (user.isEmailVerified()) {
            log.warn("Resend verification failed: email already verified: {}", email);
            throw new EmailAlreadyVerifiedException(email);
        }

        String verificationCode = verificationTokenService.createVerificationToken(user);
        emailService.sendVerificationEmail(user.getEmail(), verificationCode);

        log.debug("Verification code resent to: {}", email);
    }

    /**
     * Fordert einen Passwort-Reset an.
     *
     * Sendet eine E-Mail mit Reset-Code an die angegebene Adresse.
     * Gibt absichtlich keinen Hinweis, ob die E-Mail existiert,
     * um User-Enumeration zu verhindern.
     *
     * @param email E-Mail-Adresse des Users
     */
    @Transactional
    public void requestPasswordReset(String email) {
        var userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            log.debug("Password reset requested for non-existent email: {}", email);
            return;
        }

        User user = userOptional.get();
        String resetCode = passwordResetTokenService.createPasswordResetToken(user);
        emailService.sendPasswordResetEmail(user.getEmail(), resetCode);

        log.info("Password reset requested for user: {}", email);
    }

    /**
     * Setzt das Passwort zurück.
     *
     * Validiert den Reset-Code, aktualisiert das Passwort und
     * invalidiert alle bestehenden Refresh-Tokens des Users
     * (erzwingt Neuanmeldung auf allen Geräten).
     *
     * @param code        Reset-Code aus der E-Mail
     * @param newPassword neues Passwort im Klartext
     * @throws com.microservice.auth_service.exceptions.InvalidPasswordResetCodeException wenn Code ungültig
     * @throws com.microservice.auth_service.exceptions.PasswordResetCodeExpiredException wenn Code abgelaufen
     */
    @Transactional
    public void resetPassword(String code, String newPassword) {
        PasswordResetToken token = passwordResetTokenService.validateToken(code);
        User user = token.getUser();

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenService.deleteToken(token);

        // Invalidiere alle Refresh-Tokens (Logout from all devices)
        refreshTokenService.revokeAllTokensForUser(user);

        log.info("Password reset completed for user: {}", user.getEmail());
    }
}