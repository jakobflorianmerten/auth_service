package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.InvalidRefreshTokenException;
import com.microservice.auth_service.model.RefreshToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtService jwtService;

    private RefreshTokenService refreshTokenService;

    @Captor
    private ArgumentCaptor<RefreshToken> tokenCaptor;

    private User testUser;
    private User differentUser;

    private static final String TEST_JWT = "test.jwt.token";
    private static final long REFRESH_TOKEN_EXPIRATION = 604800000L; // 7 days

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, jwtService);
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpiration", REFRESH_TOKEN_EXPIRATION);

        testUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .emailVerified(true)
                .build();

        differentUser = User.builder()
                .id(2L)
                .email("other@example.com")
                .password("encodedPassword")
                .enabled(true)
                .emailVerified(true)
                .build();
    }

    @Nested
    @DisplayName("createRefreshToken Tests")
    class CreateRefreshTokenTests {

        @Test
        @DisplayName("Should create refresh token with hashed value")
        void shouldCreateRefreshTokenWithHash() {
            when(jwtService.generateRefreshToken(testUser)).thenReturn(TEST_JWT);
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            String result = refreshTokenService.createRefreshToken(testUser, null);

            assertThat(result).isEqualTo(TEST_JWT);
            verify(refreshTokenRepository).save(tokenCaptor.capture());

            RefreshToken savedToken = tokenCaptor.getValue();
            assertThat(savedToken.getTokenHash()).isNotEqualTo(TEST_JWT); // Hash should be different
            assertThat(savedToken.getUser()).isEqualTo(testUser);
            assertThat(savedToken.isRevoked()).isFalse();
        }

        @Test
        @DisplayName("Should set correct expiration time")
        void shouldSetCorrectExpirationTime() {
            when(jwtService.generateRefreshToken(testUser)).thenReturn(TEST_JWT);
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            LocalDateTime before = LocalDateTime.now().plusDays(6);
            refreshTokenService.createRefreshToken(testUser, null);
            LocalDateTime after = LocalDateTime.now().plusDays(8);

            verify(refreshTokenRepository).save(tokenCaptor.capture());
            RefreshToken savedToken = tokenCaptor.getValue();

            assertThat(savedToken.getExpiresAt()).isAfter(before);
            assertThat(savedToken.getExpiresAt()).isBefore(after);
        }

        @Test
        @DisplayName("Should store device info when provided")
        void shouldStoreDeviceInfo() {
            String deviceInfo = "Chrome/Windows";
            when(jwtService.generateRefreshToken(testUser)).thenReturn(TEST_JWT);
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            refreshTokenService.createRefreshToken(testUser, deviceInfo);

            verify(refreshTokenRepository).save(tokenCaptor.capture());
            assertThat(tokenCaptor.getValue().getDeviceInfo()).isEqualTo(deviceInfo);
        }

        @Test
        @DisplayName("Should handle null device info")
        void shouldHandleNullDeviceInfo() {
            when(jwtService.generateRefreshToken(testUser)).thenReturn(TEST_JWT);
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            refreshTokenService.createRefreshToken(testUser, null);

            verify(refreshTokenRepository).save(tokenCaptor.capture());
            assertThat(tokenCaptor.getValue().getDeviceInfo()).isNull();
        }
    }

    @Nested
    @DisplayName("validateAndUseToken Tests")
    class ValidateAndUseTokenTests {

        @Test
        @DisplayName("Should return user for valid token")
        void shouldReturnUserForValidToken() {
            RefreshToken validToken = RefreshToken.builder()
                    .id(1L)
                    .tokenHash(hashToken(TEST_JWT))
                    .user(testUser)
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .revoked(false)
                    .build();

            when(jwtService.isRefreshTokenValid(TEST_JWT)).thenReturn(true);
            when(refreshTokenRepository.findByTokenHash(hashToken(TEST_JWT)))
                    .thenReturn(Optional.of(validToken));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            User result = refreshTokenService.validateAndUseToken(TEST_JWT);

            assertThat(result).isEqualTo(testUser);
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("Should update lastUsedAt on validation")
        void shouldUpdateLastUsedAt() {
            LocalDateTime originalLastUsed = LocalDateTime.now().minusDays(1);
            RefreshToken validToken = RefreshToken.builder()
                    .id(1L)
                    .tokenHash(hashToken(TEST_JWT))
                    .user(testUser)
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .revoked(false)
                    .lastUsedAt(originalLastUsed)
                    .build();

            when(jwtService.isRefreshTokenValid(TEST_JWT)).thenReturn(true);
            when(refreshTokenRepository.findByTokenHash(hashToken(TEST_JWT)))
                    .thenReturn(Optional.of(validToken));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            refreshTokenService.validateAndUseToken(TEST_JWT);

            verify(refreshTokenRepository).save(tokenCaptor.capture());
            assertThat(tokenCaptor.getValue().getLastUsedAt()).isAfter(originalLastUsed);
        }

        @Test
        @DisplayName("Should throw exception for invalid JWT")
        void shouldThrowExceptionForInvalidJwt() {
            when(jwtService.isRefreshTokenValid("invalid.token")).thenReturn(false);

            assertThatThrownBy(() -> refreshTokenService.validateAndUseToken("invalid.token"))
                    .isInstanceOf(InvalidRefreshTokenException.class);

            verify(refreshTokenRepository, never()).findByTokenHash(any());
        }

        @Test
        @DisplayName("Should throw exception when token not found in database")
        void shouldThrowExceptionWhenTokenNotFound() {
            when(jwtService.isRefreshTokenValid(TEST_JWT)).thenReturn(true);
            when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.validateAndUseToken(TEST_JWT))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        }

        @Test
        @DisplayName("Should throw exception for revoked token")
        void shouldThrowExceptionForRevokedToken() {
            RefreshToken revokedToken = RefreshToken.builder()
                    .id(1L)
                    .tokenHash(hashToken(TEST_JWT))
                    .user(testUser)
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .revoked(true)
                    .build();

            when(jwtService.isRefreshTokenValid(TEST_JWT)).thenReturn(true);
            when(refreshTokenRepository.findByTokenHash(hashToken(TEST_JWT)))
                    .thenReturn(Optional.of(revokedToken));

            assertThatThrownBy(() -> refreshTokenService.validateAndUseToken(TEST_JWT))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        }

        @Test
        @DisplayName("Should throw exception for expired token in database")
        void shouldThrowExceptionForExpiredDbToken() {
            RefreshToken expiredToken = RefreshToken.builder()
                    .id(1L)
                    .tokenHash(hashToken(TEST_JWT))
                    .user(testUser)
                    .expiresAt(LocalDateTime.now().minusDays(1))
                    .revoked(false)
                    .build();

            when(jwtService.isRefreshTokenValid(TEST_JWT)).thenReturn(true);
            when(refreshTokenRepository.findByTokenHash(hashToken(TEST_JWT)))
                    .thenReturn(Optional.of(expiredToken));

            assertThatThrownBy(() -> refreshTokenService.validateAndUseToken(TEST_JWT))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        }
    }

    @Nested
    @DisplayName("revokeTokenForUser Tests")
    class RevokeTokenForUserTests {

        @Test
        @DisplayName("Should revoke token successfully")
        void shouldRevokeTokenSuccessfully() {
            RefreshToken token = RefreshToken.builder()
                    .id(1L)
                    .tokenHash(hashToken(TEST_JWT))
                    .user(testUser)
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .revoked(false)
                    .build();

            when(refreshTokenRepository.findByTokenHash(hashToken(TEST_JWT)))
                    .thenReturn(Optional.of(token));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            refreshTokenService.revokeTokenForUser(TEST_JWT, testUser);

            verify(refreshTokenRepository).save(tokenCaptor.capture());
            assertThat(tokenCaptor.getValue().isRevoked()).isTrue();
        }

        @Test
        @DisplayName("Should throw exception when token not found")
        void shouldThrowExceptionWhenTokenNotFound() {
            when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.revokeTokenForUser(TEST_JWT, testUser))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        }

        @Test
        @DisplayName("Should throw exception when token belongs to different user")
        void shouldThrowExceptionWhenTokenBelongsToDifferentUser() {
            RefreshToken token = RefreshToken.builder()
                    .id(1L)
                    .tokenHash(hashToken(TEST_JWT))
                    .user(differentUser)
                    .expiresAt(LocalDateTime.now().plusDays(1))
                    .revoked(false)
                    .build();

            when(refreshTokenRepository.findByTokenHash(hashToken(TEST_JWT)))
                    .thenReturn(Optional.of(token));

            assertThatThrownBy(() -> refreshTokenService.revokeTokenForUser(TEST_JWT, testUser))
                    .isInstanceOf(InvalidRefreshTokenException.class);

            verify(refreshTokenRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("revokeAllTokensForUser Tests")
    class RevokeAllTokensForUserTests {

        @Test
        @DisplayName("Should revoke all tokens for user")
        void shouldRevokeAllTokensForUser() {
            refreshTokenService.revokeAllTokensForUser(testUser);

            verify(refreshTokenRepository).revokeAllByUser(testUser);
        }
    }

    @Nested
    @DisplayName("cleanupExpiredTokens Tests")
    class CleanupExpiredTokensTests {

        @Test
        @DisplayName("Should delete expired tokens")
        void shouldDeleteExpiredTokens() {
            when(refreshTokenRepository.deleteByExpiresAtBefore(any(LocalDateTime.class)))
                    .thenReturn(5);

            refreshTokenService.cleanupExpiredTokens();

            verify(refreshTokenRepository).deleteByExpiresAtBefore(any(LocalDateTime.class));
        }
    }

    /**
     * Helper method to hash a token the same way the service does.
     */
    private String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
