package com.jinforce.backend.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jinforce.backend.exception.TokenException;
import com.jinforce.backend.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT 토큰 인증 필터
 * 모든 HTTP 요청에 대해 JWT 토큰을 검증하고 인증 정보를 설정
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    /**
     * 필터 내부 처리 로직
     * 1. 요청에서 JWT 토큰 추출
     * 2. 토큰 유효성 검증
     * 3. 인증 객체 생성 및 SecurityContext에 설정
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtService.validateToken(jwt)) {
                Authentication authentication = jwtService.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(request, response);
        } catch (TokenException e) {
            log.error("JWT 인증 오류: {}", e.getMessage());
            handleAuthenticationException(response, e.getMessage());
        } catch (Exception e) {
            log.error("인증 처리 중 예상치 못한 오류 발생", e);
            handleAuthenticationException(response, "인증 처리 중 오류가 발생했습니다");
        }
    }

    /**
     * 인증 예외 처리를 위한 응답 생성
     */
    private void handleAuthenticationException(HttpServletResponse response, String errorMessage) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        
        Map<String, String> error = new HashMap<>();
        error.put("error", "인증 오류");
        error.put("message", errorMessage);
        
        objectMapper.writeValue(response.getWriter(), error);
    }

    /**
     * HTTP 요청 헤더에서 JWT 토큰 추출
     * Authorization 헤더의 "Bearer " 다음 부분을 토큰으로 가져옴
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
