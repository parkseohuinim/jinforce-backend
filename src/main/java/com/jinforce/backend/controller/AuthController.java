package com.jinforce.backend.controller;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 인증 관련 API 엔드포인트 컨트롤러
 * 소셜 로그인, 토큰 갱신, 사용자 정보 조회 및 로그아웃 기능 제공
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Google OAuth2를 통한 인증 처리
     * 클라이언트로부터 받은 구글 액세스 토큰을 검증하고 JWT 토큰 발급
     */
    @PostMapping("/google")
    public ResponseEntity<TokenDto> authenticateWithGoogle(
            @RequestBody TokenDto.GoogleAuthRequest authRequest) {
        TokenDto token = authService.authenticateWithGoogle(authRequest);
        return ResponseEntity.ok(token);
    }

    /**
     * 리프레시 토큰을 사용하여 새로운 JWT 토큰 발급
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenDto> refreshToken(
            @RequestBody TokenDto.Request request) {
        TokenDto token = authService.refreshToken(request.getToken());
        return ResponseEntity.ok(token);
    }

    /**
     * 현재 인증된 사용자 정보 조회
     */
    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = authService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    /**
     * 사용자 로그아웃 처리
     * 리프레시 토큰 무효화
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody TokenDto.Request request) {
        authService.logout(request.getToken());
        return ResponseEntity.ok().build();
    }
}