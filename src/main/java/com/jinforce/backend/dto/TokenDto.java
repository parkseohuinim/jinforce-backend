package com.jinforce.backend.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Schema(description = "토큰 정보 DTO")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenDto {

    @Schema(description = "JWT 액세스 토큰", example = "abcdefgh...")
    private String accessToken;
    
    @Schema(description = "리프레시 토큰", example = "abcdefgh...")
    private String refreshToken;
    
    @Schema(description = "토큰 타입", example = "Bearer")
    private String tokenType;
    
    @Schema(description = "토큰 만료 시간(초)", example = "3600")
    private Long expiresIn;

    @Schema(description = "토큰 요청 DTO")
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Request {
        @Schema(description = "리프레시 토큰", example = "abcdefgh...")
        private String refreshToken;
    }

    /**
     * 구글 인증 요청 DTO
     * 네이티브 앱에서 구글 로그인 후 받은 액세스 토큰을 서버로 전송하기 위한 객체
     */
    @Schema(description = "구글 인증 요청 DTO")
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GoogleAuthRequest {
        @Schema(description = "구글 API 액세스 토큰", example = "abcdefgh...")
        private String accessToken; // 구글 API 호출에 필요한 액세스 토큰
    }
}
