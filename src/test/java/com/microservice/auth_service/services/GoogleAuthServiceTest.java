package com.microservice.auth_service.services;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.microservice.auth_service.configuration.GoogleProperties;
import com.microservice.auth_service.exceptions.GoogleEmailNotVerifiedException;
import com.microservice.auth_service.exceptions.InvalidGoogleTokenException;
import com.microservice.auth_service.exceptions.UserAlreadyExistsException;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.UserRepository;
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

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GoogleAuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private GoogleIdTokenVerifier verifier;

    @Mock
    private GoogleIdToken idToken;

    @Mock
    private GoogleIdToken.Payload payload;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    private GoogleAuthService googleAuthService;

    private static final String TEST_EMAIL = "test@gmail.com";
    private static final String TEST_GOOGLE_ID = "google-user-id-123";
    private static final String TEST_TOKEN = "valid.google.id.token";

    @BeforeEach
    void setUp() {
        GoogleProperties googleProperties = new GoogleProperties();
        googleProperties.setClientIds(List.of("test-client-id"));

        googleAuthService = new GoogleAuthService(userRepository, googleProperties);

        // Inject mock verifier using reflection
        ReflectionTestUtils.setField(googleAuthService, "verifier", verifier);
    }

    @Nested
    @DisplayName("authenticateWithGoogle Tests - New User")
    class NewUserTests {

        @Test
        @DisplayName("Should create new user when user does not exist")
        void shouldCreateNewUserWhenNotExists() throws Exception {
            when(verifier.verify(TEST_TOKEN)).thenReturn(idToken);
            when(idToken.getPayload()).thenReturn(payload);
            when(payload.getEmail()).thenReturn(TEST_EMAIL);
            when(payload.getSubject()).thenReturn(TEST_GOOGLE_ID);
            when(payload.getEmailVerified()).thenReturn(true);
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(1L);
                return user;
            });

            User result = googleAuthService.authenticateWithGoogle(TEST_TOKEN);

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo(TEST_EMAIL);

            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getProvider()).isEqualTo("google");
            assertThat(savedUser.getProviderId()).isEqualTo(TEST_GOOGLE_ID);
            assertThat(savedUser.isEnabled()).isTrue();
            assertThat(savedUser.isEmailVerified()).isTrue();
        }
    }

    @Nested
    @DisplayName("authenticateWithGoogle Tests - Existing Google User")
    class ExistingGoogleUserTests {

        @Test
        @DisplayName("Should allow login for existing Google user")
        void shouldAllowLoginForExistingGoogleUser() throws Exception {
            User existingUser = User.builder()
                    .id(1L)
                    .email(TEST_EMAIL)
                    .provider("google")
                    .providerId(TEST_GOOGLE_ID)
                    .enabled(true)
                    .emailVerified(true)
                    .build();

            when(verifier.verify(TEST_TOKEN)).thenReturn(idToken);
            when(idToken.getPayload()).thenReturn(payload);
            when(payload.getEmail()).thenReturn(TEST_EMAIL);
            when(payload.getSubject()).thenReturn(TEST_GOOGLE_ID);
            when(payload.getEmailVerified()).thenReturn(true);
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingUser));

            User result = googleAuthService.authenticateWithGoogle(TEST_TOKEN);

            assertThat(result).isEqualTo(existingUser);
            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("authenticateWithGoogle Tests - User with Password")
    class UserWithPasswordTests {

        @Test
        @DisplayName("Should reject login when user has password")
        void shouldRejectLoginWhenUserHasPassword() throws Exception {
            User existingUser = User.builder()
                    .id(1L)
                    .email(TEST_EMAIL)
                    .password("encoded-password")
                    .enabled(true)
                    .emailVerified(true)
                    .build();

            when(verifier.verify(TEST_TOKEN)).thenReturn(idToken);
            when(idToken.getPayload()).thenReturn(payload);
            when(payload.getEmail()).thenReturn(TEST_EMAIL);
            when(payload.getSubject()).thenReturn(TEST_GOOGLE_ID);
            when(payload.getEmailVerified()).thenReturn(true);
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingUser));

            assertThatThrownBy(() -> googleAuthService.authenticateWithGoogle(TEST_TOKEN))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessageContaining("already exists");

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("authenticateWithGoogle Tests - Unverified Email")
    class UnverifiedEmailTests {

        @Test
        @DisplayName("Should reject login when Google email is not verified")
        void shouldRejectLoginWhenEmailNotVerified() throws Exception {
            when(verifier.verify(TEST_TOKEN)).thenReturn(idToken);
            when(idToken.getPayload()).thenReturn(payload);
            when(payload.getEmail()).thenReturn(TEST_EMAIL);
            when(payload.getSubject()).thenReturn(TEST_GOOGLE_ID);
            when(payload.getEmailVerified()).thenReturn(false);

            assertThatThrownBy(() -> googleAuthService.authenticateWithGoogle(TEST_TOKEN))
                    .isInstanceOf(GoogleEmailNotVerifiedException.class);

            verify(userRepository, never()).findByEmail(any());
            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("authenticateWithGoogle Tests - Invalid Token")
    class InvalidTokenTests {

        @Test
        @DisplayName("Should throw exception for invalid token")
        void shouldThrowExceptionForInvalidToken() throws Exception {
            when(verifier.verify("invalid.token")).thenReturn(null);

            assertThatThrownBy(() -> googleAuthService.authenticateWithGoogle("invalid.token"))
                    .isInstanceOf(InvalidGoogleTokenException.class);

            verify(userRepository, never()).findByEmail(any());
        }

        @Test
        @DisplayName("Should throw exception when verification fails")
        void shouldThrowExceptionWhenVerificationFails() throws Exception {
            when(verifier.verify(TEST_TOKEN)).thenThrow(new RuntimeException("Network error"));

            assertThatThrownBy(() -> googleAuthService.authenticateWithGoogle(TEST_TOKEN))
                    .isInstanceOf(InvalidGoogleTokenException.class);

            verify(userRepository, never()).findByEmail(any());
        }
    }

    @Nested
    @DisplayName("authenticateWithGoogle Tests - Account Linking")
    class AccountLinkingTests {

        @Test
        @DisplayName("Should link Google account for user without password")
        void shouldLinkGoogleAccountForUserWithoutPassword() throws Exception {
            User userWithoutPassword = User.builder()
                    .id(1L)
                    .email(TEST_EMAIL)
                    .password(null)
                    .provider(null)
                    .providerId(null)
                    .enabled(false)
                    .emailVerified(false)
                    .build();

            when(verifier.verify(TEST_TOKEN)).thenReturn(idToken);
            when(idToken.getPayload()).thenReturn(payload);
            when(payload.getEmail()).thenReturn(TEST_EMAIL);
            when(payload.getSubject()).thenReturn(TEST_GOOGLE_ID);
            when(payload.getEmailVerified()).thenReturn(true);
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(userWithoutPassword));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            User result = googleAuthService.authenticateWithGoogle(TEST_TOKEN);

            assertThat(result.getProvider()).isEqualTo("google");
            assertThat(result.getProviderId()).isEqualTo(TEST_GOOGLE_ID);
            assertThat(result.isEnabled()).isTrue();
            assertThat(result.isEmailVerified()).isTrue();

            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getProvider()).isEqualTo("google");
        }

        @Test
        @DisplayName("Should link Google account for user with empty password")
        void shouldLinkGoogleAccountForUserWithEmptyPassword() throws Exception {
            User userWithEmptyPassword = User.builder()
                    .id(1L)
                    .email(TEST_EMAIL)
                    .password("")
                    .provider(null)
                    .providerId(null)
                    .enabled(false)
                    .emailVerified(false)
                    .build();

            when(verifier.verify(TEST_TOKEN)).thenReturn(idToken);
            when(idToken.getPayload()).thenReturn(payload);
            when(payload.getEmail()).thenReturn(TEST_EMAIL);
            when(payload.getSubject()).thenReturn(TEST_GOOGLE_ID);
            when(payload.getEmailVerified()).thenReturn(true);
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(userWithEmptyPassword));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            User result = googleAuthService.authenticateWithGoogle(TEST_TOKEN);

            assertThat(result.getProvider()).isEqualTo("google");
            verify(userRepository).save(any());
        }
    }
}
