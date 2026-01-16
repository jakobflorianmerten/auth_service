package com.microservice.auth_service.services;

import com.microservice.auth_service.dto.request.RegisterRequest;
import com.microservice.auth_service.dto.response.AuthResponse;
import com.microservice.auth_service.exceptions.EmailAlreadyVerifiedException;
import com.microservice.auth_service.exceptions.UserAlreadyExistsException;
import com.microservice.auth_service.exceptions.UserNotFoundException;
import com.microservice.auth_service.model.EmailVerificationToken;
import com.microservice.auth_service.model.PasswordResetToken;
import com.microservice.auth_service.model.User;
import com.microservice.auth_service.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private EmailVerificationTokenService verificationTokenService;

    @Mock
    private EmailService emailService;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private PasswordResetTokenService passwordResetTokenService;

    @InjectMocks
    private UserService userService;

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

        ReflectionTestUtils.setField(userService, "accessTokenExpiration", 3600000L);
    }

    @Nested
    @DisplayName("loadUserByUsername Tests")
    class LoadUserByUsernameTests {

        @Test
        @DisplayName("Should return user when found by email")
        void shouldReturnUserWhenFound() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            var result = userService.loadUserByUsername("test@example.com");

            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo("test@example.com");
            verify(userRepository).findByEmail("test@example.com");
        }

        @Test
        @DisplayName("Should throw UsernameNotFoundException when user not found")
        void shouldThrowExceptionWhenUserNotFound() {
            when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.loadUserByUsername("unknown@example.com"))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessageContaining("unknown@example.com");
        }
    }

    @Nested
    @DisplayName("registerUser Tests")
    class RegisterUserTests {

        @Test
        @DisplayName("Should register new user successfully")
        void shouldRegisterNewUser() {
            RegisterRequest request = new RegisterRequest("new@example.com", "password123");

            when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
            when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                user.setId(1L);
                return user;
            });
            when(verificationTokenService.createVerificationToken(any(User.class))).thenReturn("123456");

            User result = userService.registerUser(request);

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo("new@example.com");
            assertThat(result.isEnabled()).isFalse();
            assertThat(result.isEmailVerified()).isFalse();

            verify(userRepository).existsByEmail("new@example.com");
            verify(passwordEncoder).encode("password123");
            verify(userRepository).save(any(User.class));
            verify(verificationTokenService).createVerificationToken(any(User.class));
            verify(emailService).sendVerificationEmail("new@example.com", "123456");
        }

        @Test
        @DisplayName("Should throw exception when email already exists")
        void shouldThrowExceptionWhenEmailExists() {
            RegisterRequest request = new RegisterRequest("existing@example.com", "password123");

            when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

            assertThatThrownBy(() -> userService.registerUser(request))
                    .isInstanceOf(UserAlreadyExistsException.class);

            verify(userRepository).existsByEmail("existing@example.com");
            verify(userRepository, never()).save(any(User.class));
        }
    }

    @Nested
    @DisplayName("verifyEmail Tests")
    class VerifyEmailTests {

        @Test
        @DisplayName("Should verify email and return auth tokens")
        void shouldVerifyEmailSuccessfully() {
            User unverifiedUser = User.builder()
                    .id(1L)
                    .email("test@example.com")
                    .password("encodedPassword")
                    .enabled(false)
                    .emailVerified(false)
                    .build();

            EmailVerificationToken token = EmailVerificationToken.builder()
                    .id(1L)
                    .token("123456")
                    .user(unverifiedUser)
                    .expiryDate(LocalDateTime.now().plusHours(24))
                    .build();

            when(verificationTokenService.validateToken("123456")).thenReturn(token);
            when(userRepository.save(any(User.class))).thenReturn(unverifiedUser);
            when(jwtService.generateAccessToken(any(User.class))).thenReturn("accessToken");
            when(refreshTokenService.createRefreshToken(any(User.class), isNull())).thenReturn("refreshToken");

            AuthResponse result = userService.verifyEmail("123456");

            assertThat(result).isNotNull();
            assertThat(result.getAccessToken()).isEqualTo("accessToken");
            assertThat(result.getRefreshToken()).isEqualTo("refreshToken");
            assertThat(result.getTokenType()).isEqualTo("Bearer");
            assertThat(unverifiedUser.isEmailVerified()).isTrue();
            assertThat(unverifiedUser.isEnabled()).isTrue();

            verify(verificationTokenService).validateToken("123456");
            verify(userRepository).save(unverifiedUser);
            verify(verificationTokenService).deleteToken(token);
        }
    }

    @Nested
    @DisplayName("resendVerificationCode Tests")
    class ResendVerificationCodeTests {

        @Test
        @DisplayName("Should resend verification code successfully")
        void shouldResendVerificationCode() {
            User unverifiedUser = User.builder()
                    .id(1L)
                    .email("test@example.com")
                    .emailVerified(false)
                    .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(unverifiedUser));
            when(verificationTokenService.createVerificationToken(unverifiedUser)).thenReturn("654321");

            userService.resendVerificationCode("test@example.com");

            verify(verificationTokenService).createVerificationToken(unverifiedUser);
            verify(emailService).sendVerificationEmail("test@example.com", "654321");
        }

        @Test
        @DisplayName("Should throw exception when user not found")
        void shouldThrowExceptionWhenUserNotFound() {
            when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.resendVerificationCode("unknown@example.com"))
                    .isInstanceOf(UserNotFoundException.class);
        }

        @Test
        @DisplayName("Should throw exception when email already verified")
        void shouldThrowExceptionWhenEmailAlreadyVerified() {
            User verifiedUser = User.builder()
                    .id(1L)
                    .email("test@example.com")
                    .emailVerified(true)
                    .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(verifiedUser));

            assertThatThrownBy(() -> userService.resendVerificationCode("test@example.com"))
                    .isInstanceOf(EmailAlreadyVerifiedException.class);
        }
    }

    @Nested
    @DisplayName("requestPasswordReset Tests")
    class RequestPasswordResetTests {

        @Test
        @DisplayName("Should send password reset email when user exists")
        void shouldSendPasswordResetEmail() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordResetTokenService.createPasswordResetToken(testUser)).thenReturn("reset123");

            userService.requestPasswordReset("test@example.com");

            verify(passwordResetTokenService).createPasswordResetToken(testUser);
            verify(emailService).sendPasswordResetEmail("test@example.com", "reset123");
        }

        @Test
        @DisplayName("Should not throw exception when user not found (security)")
        void shouldNotThrowExceptionWhenUserNotFound() {
            when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

            userService.requestPasswordReset("unknown@example.com");

            verify(passwordResetTokenService, never()).createPasswordResetToken(any());
            verify(emailService, never()).sendPasswordResetEmail(anyString(), anyString());
        }
    }

    @Nested
    @DisplayName("resetPassword Tests")
    class ResetPasswordTests {

        @Test
        @DisplayName("Should reset password successfully")
        void shouldResetPassword() {
            PasswordResetToken token = PasswordResetToken.builder()
                    .id(1L)
                    .token("reset123")
                    .user(testUser)
                    .expiryDate(LocalDateTime.now().plusHours(1))
                    .build();

            when(passwordResetTokenService.validateToken("reset123")).thenReturn(token);
            when(passwordEncoder.encode("newPassword")).thenReturn("encodedNewPassword");
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            userService.resetPassword("reset123", "newPassword");

            verify(passwordResetTokenService).validateToken("reset123");
            verify(passwordEncoder).encode("newPassword");
            verify(userRepository).save(testUser);
            verify(passwordResetTokenService).deleteToken(token);
            verify(refreshTokenService).revokeAllTokensForUser(testUser);
        }
    }
}