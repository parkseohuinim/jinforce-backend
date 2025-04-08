package com.jinforce.backend.controller;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 인증 관련 API 엔드포인트 컨트롤러
 * 소셜 로그인, 토큰 갱신, 사용자 정보 조회 및 로그아웃 기능 제공
 */
@Tag(name = "Authentication", description = "인증 관련 API")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Google OAuth2를 통한 인증 처리
     * 클라이언트로부터 받은 구글 액세스 토큰을 검증하고 JWT 토큰 발급
     */
    @Operation(
        summary = "Google 로그인", 
        description = "Google OAuth 액세스 토큰으로 로그인하고 JWT 토큰을 발급받습니다"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "로그인 성공", 
            content = @Content(schema = @Schema(implementation = TokenDto.class))
        ),
        @ApiResponse(responseCode = "401", description = "인증 실패", content = @Content)
    })
    @PostMapping("/google")
    public ResponseEntity<TokenDto> authenticateWithGoogle(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "Google 액세스 토큰", 
                required = true, 
                content = @Content(schema = @Schema(implementation = TokenDto.GoogleAuthRequest.class))
            )
            @RequestBody TokenDto.GoogleAuthRequest authRequest) {
        TokenDto token = authService.authenticateWithGoogle(authRequest);
        return ResponseEntity.ok(token);
    }

    /**
     * 리프레시 토큰을 사용하여 새로운 JWT 토큰 발급
     */
    @Operation(
        summary = "토큰 갱신", 
        description = "리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급받습니다"
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "토큰 갱신 성공", 
            content = @Content(schema = @Schema(implementation = TokenDto.class))
        ),
        @ApiResponse(responseCode = "401", description = "유효하지 않은 리프레시 토큰", content = @Content)
    })
    @PostMapping("/refresh")
    public ResponseEntity<TokenDto> refreshToken(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "리프레시 토큰", 
                required = true,
                content = @Content(schema = @Schema(implementation = TokenDto.Request.class))
            )
            @RequestBody TokenDto.Request request) {
        TokenDto token = authService.refreshToken(request.getToken());
        return ResponseEntity.ok(token);
    }

    /**
     * 현재 인증된 사용자 정보 조회
     */
    @Operation(
        summary = "사용자 정보 조회", 
        description = "현재 인증된 사용자의 정보를 조회합니다",
        security = { @SecurityRequirement(name = "JWT") }
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "조회 성공", 
            content = @Content(schema = @Schema(implementation = UserDto.class))
        ),
        @ApiResponse(responseCode = "401", description = "인증 필요", content = @Content)
    })
    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = authService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    /**
     * 사용자 로그아웃 처리
     * 리프레시 토큰 무효화
     */
    @Operation(
        summary = "로그아웃", 
        description = "사용자 세션을 종료하고 리프레시 토큰을 무효화합니다",
        security = { @SecurityRequirement(name = "JWT") }
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "로그아웃 성공", content = @Content),
        @ApiResponse(responseCode = "401", description = "인증 필요", content = @Content)
    })
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "리프레시 토큰", 
                required = true,
                content = @Content(schema = @Schema(implementation = TokenDto.Request.class))
            )
            @RequestBody TokenDto.Request request) {
        authService.logout(request.getToken());
        return ResponseEntity.ok().build();
    }
}