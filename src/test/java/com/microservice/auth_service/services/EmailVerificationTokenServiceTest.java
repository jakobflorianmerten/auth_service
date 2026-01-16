package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.InvalidVerificationCodeException;
import com.microservice.auth_service.exceptions.VerificationCodeExpiredException;
import com.microservice.auth_service.model.EmailVerificationToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.EmailVerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailVerificationTokenServiceTest {

    @Mock
    private EmailVerificationTokenRepository tokenRepository;

    @InjectMocks
    private EmailVerificationTokenService tokenService;

    @Captor
    private ArgumentCaptor<EmailVerificationToken> tokenCaptor;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(false)
                .emailVerified(false)
                .build();
    }

    @Nested
    @DisplayName("createVerificationToken Tests")
    class CreateVerificationTokenTests {

        @Test
        @DisplayName("Should create 6-digit verification code")
        void shouldCreate6DigitCode() {
            when(tokenRepository.save(any(EmailVerificationToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            String code = tokenService.createVerificationToken(testUser);

            assertThat(code).hasSize(6);
            assertThat(code).matches("\\d{6}"); // Only digits
        }

        @Test
        @DisplayName("Should delete existing tokens before creating new one")
        void shouldDeleteExistingTokens() {
            when(tokenRepository.save(any(EmailVerificationToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            tokenService.createVerificationToken(testUser);

            verify(tokenRepository).deleteByUser(testUser);
            verify(tokenRepository).save(any(EmailVerificationToken.class));
        }

        @Test
        @DisplayName("Should set expiry date 24 hours in future")
        void shouldSetExpiryDate24Hours() {
            when(tokenRepository.save(any(EmailVerificationToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            LocalDateTime before = LocalDateTime.now().plusHours(23).plusMinutes(59);
            tokenService.createVerificationToken(testUser);
            LocalDateTime after = LocalDateTime.now().plusHours(24).plusMinutes(1);

            verify(tokenRepository).save(tokenCaptor.capture());
            EmailVerificationToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getExpiryDate()).isAfter(before);
            assertThat(savedToken.getExpiryDate()).isBefore(after);
        }

        @Test
        @DisplayName("Should associate token with correct user")
        void shouldAssociateTokenWithUser() {
            when(tokenRepository.save(any(EmailVerificationToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            tokenService.createVerificationToken(testUser);

            verify(tokenRepository).save(tokenCaptor.capture());
            assertThat(tokenCaptor.getValue().getUser()).isEqualTo(testUser);
        }

        @Test
        @DisplayName("Should generate different codes on subsequent calls")
        void shouldGenerateDifferentCodes() {
            when(tokenRepository.save(any(EmailVerificationToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            String code1 = tokenService.createVerificationToken(testUser);
            String code2 = tokenService.createVerificationToken(testUser);
            String code3 = tokenService.createVerificationToken(testUser);

            // While theoretically codes could match, it's very unlikely
            // At least two of three should be different
            assertThat(code1.equals(code2) && code2.equals(code3)).isFalse();
        }
    }

    @Nested
    @DisplayName("validateToken Tests")
    class ValidateTokenTests {

        @Test
        @DisplayName("Should return token when valid")
        void shouldReturnTokenWhenValid() {
            EmailVerificationToken validToken = EmailVerificationToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().plusHours(1))
                    .build();

            when(tokenRepository.findByToken("123456")).thenReturn(Optional.of(validToken));

            EmailVerificationToken result = tokenService.validateToken("123456");

            assertThat(result).isEqualTo(validToken);
            verify(tokenRepository).findByToken("123456");
        }

        @Test
        @DisplayName("Should throw InvalidVerificationCodeException when code not found")
        void shouldThrowExceptionWhenCodeNotFound() {
            when(tokenRepository.findByToken("999999")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> tokenService.validateToken("999999"))
                    .isInstanceOf(InvalidVerificationCodeException.class);
        }

        @Test
        @DisplayName("Should throw VerificationCodeExpiredException when code expired")
        void shouldThrowExceptionWhenCodeExpired() {
            EmailVerificationToken expiredToken = EmailVerificationToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().minusHours(1))
                    .build();

            when(tokenRepository.findByToken("123456")).thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> tokenService.validateToken("123456"))
                    .isInstanceOf(VerificationCodeExpiredException.class);

            verify(tokenRepository).delete(expiredToken);
        }

        @Test
        @DisplayName("Should delete expired token when validating")
        void shouldDeleteExpiredToken() {
            EmailVerificationToken expiredToken = EmailVerificationToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().minusSeconds(1))
                    .build();

            when(tokenRepository.findByToken("123456")).thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> tokenService.validateToken("123456"))
                    .isInstanceOf(VerificationCodeExpiredException.class);

            verify(tokenRepository).delete(expiredToken);
        }
    }

    @Nested
    @DisplayName("deleteTokensByUser Tests")
    class DeleteTokensByUserTests {

        @Test
        @DisplayName("Should delete all tokens for user")
        void shouldDeleteAllTokensForUser() {
            tokenService.deleteTokensByUser(testUser);

            verify(tokenRepository).deleteByUser(testUser);
        }
    }

    @Nested
    @DisplayName("deleteToken Tests")
    class DeleteTokenTests {

        @Test
        @DisplayName("Should delete specific token")
        void shouldDeleteSpecificToken() {
            EmailVerificationToken token = EmailVerificationToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().plusHours(1))
                    .build();

            tokenService.deleteToken(token);

            verify(tokenRepository).delete(token);
        }
    }

    @Nested
    @DisplayName("deleteExpiredTokens Tests")
    class DeleteExpiredTokensTests {

        @Test
        @DisplayName("Should delete all expired tokens")
        void shouldDeleteExpiredTokens() {
            tokenService.deleteExpiredTokens();

            verify(tokenRepository).deleteByExpiryDateBefore(any(LocalDateTime.class));
        }
    }
}
