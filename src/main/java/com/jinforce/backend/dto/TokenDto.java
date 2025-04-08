package com.jinforce.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenDto {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Request {
        private String token;
    }

    /**
     * 구글 인증 요청 DTO
     * 네이티브 앱에서 구글 로그인 후 받은 액세스 토큰을 서버로 전송하기 위한 객체
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GoogleAuthRequest {
        private String accessToken; // 구글 API 호출에 필요한 액세스 토큰
    }
}
