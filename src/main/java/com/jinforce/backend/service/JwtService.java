package com.jinforce.backend.service;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.entity.User;
import org.springframework.security.core.Authentication;

/**
 * JWT 토큰 관리 서비스
 * 액세스 토큰 및 리프레시 토큰 생성, 검증, 갱신 처리
 */
public interface JwtService {

    TokenDto generateTokens(Authentication authentication);
    String createRefreshToken(String email);
    TokenDto refreshToken(String refreshToken);
    boolean validateToken(String token);
    String extractEmail(String token);
    Authentication getAuthentication(String token);
    void invalidateRefreshToken(User user);
}