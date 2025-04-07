package com.jinforce.backend.service;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.entity.RefreshToken;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.exception.TokenException;
import com.jinforce.backend.repository.RefreshTokenRepository;
import com.jinforce.backend.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private JwtService jwtService;

    private final String TEST_EMAIL = "test@example.com";
    private final String SECRET_KEY = "testSecretKeyMustBeAtLeast32BytesLongForHS256Algorithm";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtService, "secretKey", SECRET_KEY);
        ReflectionTestUtils.setField(jwtService, "accessTokenValidityInMilliseconds", 3600000L);
        ReflectionTestUtils.setField(jwtService, "refreshTokenValidityInMilliseconds", 2592000000L);
    }

    @Test
    void generateTokens_ShouldReturnTokenDto() {
        // Given
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                TEST_EMAIL, null, Collections.singletonList(authority));

        User user = User.builder()
                .email(TEST_EMAIL)
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUser(any(User.class))).thenReturn(Optional.empty());
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));

        // When
        TokenDto tokenDto = jwtService.generateTokens(authentication);

        // Then
        assertNotNull(tokenDto);
        assertNotNull(tokenDto.getAccessToken());
        assertNotNull(tokenDto.getRefreshToken());
        assertEquals("Bearer", tokenDto.getTokenType());
        assertEquals(3600L, tokenDto.getExpiresIn());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void validateToken_WithValidToken_ShouldReturnTrue() {
        // Given
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                TEST_EMAIL, null, Collections.singletonList(authority));

        User user = User.builder()
                .email(TEST_EMAIL)
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUser(any(User.class))).thenReturn(Optional.empty());
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));

        TokenDto tokenDto = jwtService.generateTokens(authentication);

        // When
        boolean isValid = jwtService.validateToken(tokenDto.getAccessToken());

        // Then
        assertTrue(isValid);
    }

    @Test
    void validateToken_WithInvalidToken_ShouldThrowException() {
        // Given
        String invalidToken = "invalid.token.here";

        // When & Then
        assertThrows(TokenException.class, () -> jwtService.validateToken(invalidToken));
    }

    @Test
    void refreshToken_ShouldReturnNewTokenDto() {
        // Given
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(TEST_EMAIL)
                .password("")
                .authorities(Collections.singletonList(authority))
                .build();

        User user = User.builder()
                .email(TEST_EMAIL)
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        // Prepare a valid token using our service
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                TEST_EMAIL, null, Collections.singletonList(authority));

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUser(any(User.class))).thenReturn(Optional.empty());
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(i -> i.getArgument(0));

        TokenDto originalTokenDto = jwtService.generateTokens(authentication);
        String validRefreshToken = originalTokenDto.getRefreshToken();

        // Mock for refreshToken method
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .token(validRefreshToken)
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(30))
                .build();

        when(refreshTokenRepository.findByToken(validRefreshToken)).thenReturn(Optional.of(refreshTokenEntity));
        when(userDetailsService.loadUserByUsername(TEST_EMAIL)).thenReturn(userDetails);

        // When
        TokenDto newTokenDto = jwtService.refreshToken(validRefreshToken);

        // Then
        assertNotNull(newTokenDto);
        assertNotNull(newTokenDto.getAccessToken());
        assertNotNull(newTokenDto.getRefreshToken());
        assertNotEquals(originalTokenDto.getAccessToken(), newTokenDto.getAccessToken());
        verify(userDetailsService).loadUserByUsername(TEST_EMAIL);
    }

    @Test
    void invalidateRefreshToken_ShouldDeleteToken() {
        // Given
        User user = User.builder()
                .email(TEST_EMAIL)
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        RefreshToken refreshToken = RefreshToken.builder()
                .token("refresh.token.value")
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(30))
                .build();

        when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.of(refreshToken));

        // When
        jwtService.invalidateRefreshToken(user);

        // Then
        verify(refreshTokenRepository).delete(refreshToken);
    }
}