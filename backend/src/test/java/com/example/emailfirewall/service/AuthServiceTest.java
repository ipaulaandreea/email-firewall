package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AuthResponse;
import com.example.emailfirewall.entity.UserEntity;
import com.example.emailfirewall.exception.InvalidCredentialsException;
import com.example.emailfirewall.exception.UserAlreadyExistsException;
import com.example.emailfirewall.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
class AuthServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;

    @InjectMocks AuthService authService;

    @BeforeEach
    void setUpJwtProps() {
        ReflectionTestUtils.setField(authService, "jwtSecret",
                "0123456789012345678901234567890123456789012345678901234567890123");
        ReflectionTestUtils.setField(authService, "jwtExpiration", 86400000L);
    }

    @Test
    void authenticate_success_returnsToken() {
        UserEntity u = new UserEntity();
        u.setEmail("admin@example.com");
        u.setPasswordHash("HASH");
        u.setRole("ADMIN");

        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("password123", "HASH")).thenReturn(true);

        AuthResponse res = authService.authenticate("admin@example.com", "password123");

        assertNotNull(res);
        assertEquals("admin@example.com", res.getEmail());
        assertEquals("ADMIN", res.getRole());
        assertNotNull(res.getToken());
        assertFalse(res.getToken().isBlank());

        verify(userRepository).findByEmail("admin@example.com");
        verify(passwordEncoder).matches("password123", "HASH");
    }

    @Test
    void authenticate_trimsAndLowercasesEmail() {
        UserEntity u = new UserEntity();
        u.setEmail("admin@example.com");
        u.setPasswordHash("HASH");
        u.setRole("ADMIN");

        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("password123", "HASH")).thenReturn(true);

        AuthResponse res = authService.authenticate("  Admin@Example.com  ", "password123");

        assertEquals("admin@example.com", res.getEmail());
        verify(userRepository).findByEmail("admin@example.com");
    }

    @Test
    void authenticate_userNotFound_throwsInvalidCredentials() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        InvalidCredentialsException ex = assertThrows(
                InvalidCredentialsException.class,
                () -> authService.authenticate("missing@example.com", "password123")
        );

        assertEquals("Invalid Credentials", ex.getMessage());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void authenticate_passwordMismatch_throwsInvalidCredentials() {
        UserEntity u = new UserEntity();
        u.setEmail("admin@example.com");
        u.setPasswordHash("HASH");
        u.setRole("ADMIN");

        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", "HASH")).thenReturn(false);

        InvalidCredentialsException ex = assertThrows(
                InvalidCredentialsException.class,
                () -> authService.authenticate("admin@example.com", "wrong")
        );

        assertEquals("Invalid Credentials", ex.getMessage());
        verify(passwordEncoder).matches("wrong", "HASH");
    }

    @Test
    void register_success_savesUserAndReturnsToken() {
        when(userRepository.findByEmail("newuser@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("ENC_HASH");

        ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);

        AuthResponse res = authService.register("newuser@example.com", "password123");

        assertNotNull(res);
        assertEquals("newuser@example.com", res.getEmail());
        assertNotNull(res.getToken());
        assertFalse(res.getToken().isBlank());

        verify(userRepository).save(captor.capture());
        UserEntity saved = captor.getValue();

        assertEquals("newuser@example.com", saved.getEmail());
        assertEquals("ENC_HASH", saved.getPasswordHash());

        assertEquals("ANALYST", saved.getRole());

        verify(passwordEncoder).encode("password123");
    }

    @Test
    void register_existingUser_throwsUserAlreadyExists() {
        UserEntity existing = new UserEntity();
        existing.setEmail("newuser@example.com");

        when(userRepository.findByEmail("newuser@example.com")).thenReturn(Optional.of(existing));

        UserAlreadyExistsException ex = assertThrows(
                UserAlreadyExistsException.class,
                () -> authService.register("newuser@example.com", "password123")
        );

        assertEquals("User already exists", ex.getMessage());
        verify(userRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
    }
}