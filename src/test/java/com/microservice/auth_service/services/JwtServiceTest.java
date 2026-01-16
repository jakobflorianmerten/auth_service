package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.JwtTokenException;
import com.microservice.auth_service.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;
    private User testUser;

    private static final long ACCESS_TOKEN_EXPIRATION = 3600000L; // 1 hour
    private static final long REFRESH_TOKEN_EXPIRATION = 604800000L; // 7 days
    private static final String ISSUER = "https://auth.test.com";

    @BeforeEach
    void setUp() throws Exception {
        jwtService = new JwtService();

        // Generate RSA key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Set private key using reflection
        ReflectionTestUtils.setField(jwtService, "privateKey", keyPair.getPrivate());
        ReflectionTestUtils.setField(jwtService, "publicKey", keyPair.getPublic());
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", REFRESH_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(jwtService, "issuer", ISSUER);

        testUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .password("encodedPassword")
                .enabled(true)
                .emailVerified(true)
                .build();
    }

    @Nested
    @DisplayName("generateAccessToken Tests")
    class GenerateAccessTokenTests {

        @Test
        @DisplayName("Should generate valid access token")
        void shouldGenerateValidAccessToken() {
            String token = jwtService.generateAccessToken(testUser);

            assertThat(token).isNotNull().isNotEmpty();
            assertThat(token.split("\\.")).hasSize(3); // JWT has 3 parts
        }

        @Test
        @DisplayName("Should include correct username in token")
        void shouldIncludeCorrectUsername() {
            String token = jwtService.generateAccessToken(testUser);
            String extractedUsername = jwtService.extractUsername(token);

            assertThat(extractedUsername).isEqualTo("test@example.com");
        }
    }

    @Nested
    @DisplayName("generateRefreshToken Tests")
    class GenerateRefreshTokenTests {

        @Test
        @DisplayName("Should generate valid refresh token")
        void shouldGenerateValidRefreshToken() {
            String token = jwtService.generateRefreshToken(testUser);

            assertThat(token).isNotNull().isNotEmpty();
            assertThat(token.split("\\.")).hasSize(3);
        }

        @Test
        @DisplayName("Should include correct username in refresh token")
        void shouldIncludeCorrectUsernameInRefreshToken() {
            String token = jwtService.generateRefreshToken(testUser);
            String extractedUsername = jwtService.extractUsername(token);

            assertThat(extractedUsername).isEqualTo("test@example.com");
        }
    }

    @Nested
    @DisplayName("extractUsername Tests")
    class ExtractUsernameTests {

        @Test
        @DisplayName("Should extract username from valid token")
        void shouldExtractUsernameFromValidToken() {
            String token = jwtService.generateAccessToken(testUser);

            String username = jwtService.extractUsername(token);

            assertThat(username).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("Should throw exception for invalid token")
        void shouldThrowExceptionForInvalidToken() {
            String invalidToken = "invalid.token.here";

            assertThatThrownBy(() -> jwtService.extractUsername(invalidToken))
                    .isInstanceOf(JwtTokenException.class);
        }

        @Test
        @DisplayName("Should throw exception for malformed token")
        void shouldThrowExceptionForMalformedToken() {
            String malformedToken = "not-a-jwt";

            assertThatThrownBy(() -> jwtService.extractUsername(malformedToken))
                    .isInstanceOf(JwtTokenException.class);
        }
    }

    @Nested
    @DisplayName("isTokenValid Tests")
    class IsTokenValidTests {

        @Test
        @DisplayName("Should return true for valid token matching user")
        void shouldReturnTrueForValidToken() {
            String token = jwtService.generateAccessToken(testUser);

            boolean isValid = jwtService.isTokenValid(token, testUser);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false for token with wrong user")
        void shouldReturnFalseForWrongUser() {
            String token = jwtService.generateAccessToken(testUser);

            User differentUser = User.builder()
                    .id(2L)
                    .email("other@example.com")
                    .build();

            boolean isValid = jwtService.isTokenValid(token, differentUser);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for expired token")
        void shouldReturnFalseForExpiredToken() throws Exception {
            // Set very short expiration
            ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", 1L);

            String token = jwtService.generateAccessToken(testUser);

            // Wait for token to expire
            Thread.sleep(10);

            // Reset expiration for validation
            ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);

            // Expired tokens throw JwtTokenException when parsed
            assertThatThrownBy(() -> jwtService.isTokenValid(token, testUser))
                    .isInstanceOf(JwtTokenException.class);
        }
    }

    @Nested
    @DisplayName("isRefreshTokenValid Tests")
    class IsRefreshTokenValidTests {

        @Test
        @DisplayName("Should return true for valid refresh token")
        void shouldReturnTrueForValidRefreshToken() {
            String token = jwtService.generateRefreshToken(testUser);

            boolean isValid = jwtService.isRefreshTokenValid(token);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false for invalid refresh token")
        void shouldReturnFalseForInvalidToken() {
            boolean isValid = jwtService.isRefreshTokenValid("invalid.token.here");

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for expired refresh token")
        void shouldReturnFalseForExpiredRefreshToken() throws Exception {
            // Set very short expiration
            ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", 1L);

            String token = jwtService.generateRefreshToken(testUser);

            // Wait for token to expire
            Thread.sleep(10);

            // Reset expiration
            ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", REFRESH_TOKEN_EXPIRATION);

            boolean isValid = jwtService.isRefreshTokenValid(token);

            assertThat(isValid).isFalse();
        }
    }

    @Nested
    @DisplayName("Token Tampering Tests")
    class TokenTamperingTests {

        @Test
        @DisplayName("Should reject token signed with different key")
        void shouldRejectTokenSignedWithDifferentKey() throws Exception {
            // Generate token with current key
            String token = jwtService.generateAccessToken(testUser);

            // Generate new key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair newKeyPair = keyGen.generateKeyPair();

            // Replace public key for verification
            ReflectionTestUtils.setField(jwtService, "publicKey", newKeyPair.getPublic());

            // Token should be invalid now
            assertThatThrownBy(() -> jwtService.extractUsername(token))
                    .isInstanceOf(JwtTokenException.class);
        }

        @Test
        @DisplayName("Should reject tampered token payload")
        void shouldRejectTamperedToken() {
            String token = jwtService.generateAccessToken(testUser);
            String[] parts = token.split("\\.");

            // Tamper with the payload (middle part)
            String tamperedPayload = Base64.getUrlEncoder().encodeToString("{\"sub\":\"hacker@evil.com\"}".getBytes());
            String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

            assertThatThrownBy(() -> jwtService.extractUsername(tamperedToken))
                    .isInstanceOf(JwtTokenException.class);
        }
    }
}
