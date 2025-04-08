package com.jinforce.backend.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jinforce.backend.dto.GoogleUserInfoDto;
import com.jinforce.backend.dto.OAuth2UserInfoDto;
import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.exception.TokenException;
import com.jinforce.backend.exception.UserException;
import com.jinforce.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final OAuth2UserService oAuth2UserService;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String googleUserInfoUri;

    /**
     * Google 토큰으로 인증하고 JWT 토큰을 생성합니다.
     *
     * @param authRequest 구글 인증 요청 정보(액세스 토큰)
     * @return JWT 토큰 응답
     * @throws TokenException 토큰 인증 중 오류 발생시
     */
    @Transactional
    public TokenDto authenticateWithGoogle(TokenDto.GoogleAuthRequest authRequest) {
        if (authRequest == null || authRequest.getAccessToken() == null || authRequest.getAccessToken().isBlank()) {
            throw new TokenException("Google access token is required");
        }

        try {
            // Google 사용자 정보 요청
            GoogleUserInfoDto userInfo = fetchGoogleUserInfo(authRequest.getAccessToken());

            // OAuth2 사용자 처리
            OAuth2UserInfoDto oAuth2UserInfo = OAuth2UserInfoDto.of(User.AuthProvider.GOOGLE, userInfo.toAttributeMap());
            User user = oAuth2UserService.processOAuth2User(oAuth2UserInfo);

            // 인증 객체 생성 및 컨텍스트 설정
            Authentication authentication = createAuthentication(user);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // JWT 토큰 생성
            return jwtService.generateTokens(authentication);
        } catch (HttpClientErrorException e) {
            log.error("Google API 호출 중 오류 발생: {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new TokenException("Google 인증에 실패했습니다: " + e.getStatusCode());
        } catch (RestClientException e) {
            log.error("Google API 통신 중 오류 발생", e);
            throw new TokenException("Google 서버와 통신 중 오류가 발생했습니다");
        } catch (Exception e) {
            log.error("Google 인증 처리 중 오류 발생", e);
            throw new TokenException("Google 인증 처리 중 오류가 발생했습니다");
        }
    }

    /**
     * Google API를 호출하여 사용자 정보를 가져옵니다.
     *
     * @param accessToken Google 액세스 토큰
     * @return Google 사용자 정보
     * @throws RestClientException API 호출 중 오류 발생시
     */
    private GoogleUserInfoDto fetchGoogleUserInfo(String accessToken) throws RestClientException {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<GoogleUserInfoDto> response = restTemplate.exchange(
                googleUserInfoUri,
                HttpMethod.GET,
                entity,
                GoogleUserInfoDto.class
        );

        if (response.getBody() == null) {
            throw new TokenException("Google에서 사용자 정보를 받아오지 못했습니다");
        }

        return response.getBody();
    }

    /**
     * 리프레시 토큰을 사용하여 새 JWT 토큰을 발급합니다.
     *
     * @param refreshToken 리프레시 토큰
     * @return 새로 발급된 JWT 토큰
     * @throws TokenException 리프레시 토큰이 유효하지 않은 경우
     */
    @Transactional
    public TokenDto refreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new TokenException("리프레시 토큰이 필요합니다");
        }
        return jwtService.refreshToken(refreshToken);
    }

    /**
     * 현재 인증된 사용자 정보를 조회합니다.
     *
     * @return 사용자 정보
     * @throws UserException 사용자를 찾을 수 없는 경우
     */
    @Transactional(readOnly = true)
    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getPrincipal())) {
            throw new UserException("인증되지 않은 사용자입니다");
        }

        String email = authentication.getName();
        return userRepository.findByEmail(email)
                .map(UserDto::fromEntity)
                .orElseThrow(() -> new UserException("사용자를 찾을 수 없습니다"));
    }

    /**
     * 사용자 엔티티로부터 Authentication 객체를 생성합니다.
     *
     * @param user 사용자 엔티티
     * @return Authentication 객체
     */
    private Authentication createAuthentication(User user) {
        var authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(
                user.getEmail(),
                null, // credentials
                authorities
        );
    }

    /**
     * 로그아웃 처리를 합니다.
     *
     * @param refreshToken 리프레시 토큰
     * @throws TokenException 토큰이 유효하지 않은 경우
     * @throws UserException 사용자를 찾을 수 없는 경우
     */
    @Transactional
    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new TokenException("리프레시 토큰이 필요합니다");
        }

        jwtService.validateToken(refreshToken);
        String email = jwtService.extractEmail(refreshToken);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserException("사용자를 찾을 수 없습니다"));

        // 리프레시 토큰 무효화
        jwtService.invalidateRefreshToken(user);
    }
}
