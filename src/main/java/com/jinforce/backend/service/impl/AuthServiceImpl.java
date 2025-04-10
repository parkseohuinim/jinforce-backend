package com.jinforce.backend.service.impl;

import com.jinforce.backend.dto.GoogleUserInfoDto;
import com.jinforce.backend.dto.OAuth2UserInfoDto;
import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.exception.TokenException;
import com.jinforce.backend.exception.UserException;
import com.jinforce.backend.repository.UserRepository;
import com.jinforce.backend.service.AuthService;
import com.jinforce.backend.service.CustomOAuth2UserService;
import com.jinforce.backend.service.JwtService;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final RestTemplate restTemplate;
    private final PasswordEncoder passwordEncoder;

    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String googleUserInfoUri;

    /**
     * Google 토큰으로 인증하고 JWT 토큰을 생성합니다.
     *
     * @param authRequest 구글 인증 요청 정보(액세스 토큰)
     * @return JWT 토큰 응답
     * @throws TokenException 토큰 인증 중 오류 발생시
     */
    @Override
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
            User user = customOAuth2UserService.processOAuth2User(oAuth2UserInfo);

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
    @Override
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
    @Override
    @Transactional
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
    @Override
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

    /**
     * 이메일과 비밀번호로 로그인을 처리합니다.
     *
     * @param email 이메일
     * @param password 비밀번호
     * @return JWT 토큰 응답
     * @throws UserException 사용자가 존재하지 않거나 비밀번호가 일치하지 않는 경우
     */
    @Override
    @Transactional
    public TokenDto login(String email, String password) {
        // 사용자 확인
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserException("등록되지 않은 이메일입니다."));

        // LOCAL 로그인 방식인지 확인
        if (user.getProvider() != User.AuthProvider.LOCAL) {
            throw new UserException("소셜 로그인 계정입니다. 해당 소셜 로그인을 이용해주세요: " + user.getProvider());
        }

        // 비밀번호 검증
        if (user.getPassword() == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new UserException("비밀번호가 일치하지 않습니다.");
        }

        // 인증 객체 생성
        Authentication authentication = createAuthentication(user);

        // JWT 토큰 발급
        return jwtService.generateTokens(authentication);
    }
}
