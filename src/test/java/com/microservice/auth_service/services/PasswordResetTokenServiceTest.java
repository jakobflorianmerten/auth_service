package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.InvalidPasswordResetCodeException;
import com.microservice.auth_service.exceptions.PasswordResetCodeExpiredException;
import com.microservice.auth_service.model.PasswordResetToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.PasswordResetTokenRepository;
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
class PasswordResetTokenServiceTest {

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @InjectMocks
    private PasswordResetTokenService tokenService;

    @Captor
    private ArgumentCaptor<PasswordResetToken> tokenCaptor;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .emailVerified(true)
                .build();
    }

    @Nested
    @DisplayName("createPasswordResetToken Tests")
    class CreatePasswordResetTokenTests {

        @Test
        @DisplayName("Should create 6-digit reset code")
        void shouldCreate6DigitCode() {
            when(tokenRepository.save(any(PasswordResetToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            String code = tokenService.createPasswordResetToken(testUser);

            assertThat(code).hasSize(6);
            assertThat(code).matches("\\d{6}");
        }

        @Test
        @DisplayName("Should delete existing tokens before creating new one")
        void shouldDeleteExistingTokens() {
            when(tokenRepository.save(any(PasswordResetToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            tokenService.createPasswordResetToken(testUser);

            verify(tokenRepository).deleteByUser(testUser);
            verify(tokenRepository).save(any(PasswordResetToken.class));
        }

        @Test
        @DisplayName("Should set expiry date 1 hour in future")
        void shouldSetExpiryDate1Hour() {
            when(tokenRepository.save(any(PasswordResetToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            LocalDateTime before = LocalDateTime.now().plusMinutes(59);
            tokenService.createPasswordResetToken(testUser);
            LocalDateTime after = LocalDateTime.now().plusHours(1).plusMinutes(1);

            verify(tokenRepository).save(tokenCaptor.capture());
            PasswordResetToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getExpiryDate()).isAfter(before);
            assertThat(savedToken.getExpiryDate()).isBefore(after);
        }

        @Test
        @DisplayName("Should associate token with correct user")
        void shouldAssociateTokenWithUser() {
            when(tokenRepository.save(any(PasswordResetToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            tokenService.createPasswordResetToken(testUser);

            verify(tokenRepository).save(tokenCaptor.capture());
            assertThat(tokenCaptor.getValue().getUser()).isEqualTo(testUser);
        }

        @Test
        @DisplayName("Should generate different codes on subsequent calls")
        void shouldGenerateDifferentCodes() {
            when(tokenRepository.save(any(PasswordResetToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            String code1 = tokenService.createPasswordResetToken(testUser);
            String code2 = tokenService.createPasswordResetToken(testUser);
            String code3 = tokenService.createPasswordResetToken(testUser);

            // While theoretically codes could match, it's very unlikely
            assertThat(code1.equals(code2) && code2.equals(code3)).isFalse();
        }
    }

    @Nested
    @DisplayName("validateToken Tests")
    class ValidateTokenTests {

        @Test
        @DisplayName("Should return token when valid")
        void shouldReturnTokenWhenValid() {
            PasswordResetToken validToken = PasswordResetToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().plusMinutes(30))
                    .build();

            when(tokenRepository.findByToken("123456")).thenReturn(Optional.of(validToken));

            PasswordResetToken result = tokenService.validateToken("123456");

            assertThat(result).isEqualTo(validToken);
            verify(tokenRepository).findByToken("123456");
        }

        @Test
        @DisplayName("Should throw InvalidPasswordResetCodeException when code not found")
        void shouldThrowExceptionWhenCodeNotFound() {
            when(tokenRepository.findByToken("999999")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> tokenService.validateToken("999999"))
                    .isInstanceOf(InvalidPasswordResetCodeException.class);
        }

        @Test
        @DisplayName("Should throw PasswordResetCodeExpiredException when code expired")
        void shouldThrowExceptionWhenCodeExpired() {
            PasswordResetToken expiredToken = PasswordResetToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().minusMinutes(1))
                    .build();

            when(tokenRepository.findByToken("123456")).thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> tokenService.validateToken("123456"))
                    .isInstanceOf(PasswordResetCodeExpiredException.class);

            verify(tokenRepository).delete(expiredToken);
        }

        @Test
        @DisplayName("Should delete expired token when validating")
        void shouldDeleteExpiredToken() {
            PasswordResetToken expiredToken = PasswordResetToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().minusSeconds(1))
                    .build();

            when(tokenRepository.findByToken("123456")).thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> tokenService.validateToken("123456"))
                    .isInstanceOf(PasswordResetCodeExpiredException.class);

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
            PasswordResetToken token = PasswordResetToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().plusMinutes(30))
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
