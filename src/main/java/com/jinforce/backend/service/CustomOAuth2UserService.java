package com.jinforce.backend.service;

import com.jinforce.backend.dto.OAuth2UserInfoDto;
import com.jinforce.backend.entity.User;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * OAuth2 인증 처리 서비스 인터페이스
 * 소셜 로그인 사용자의 인증 및 정보 처리
 */
public interface CustomOAuth2UserService {

    /**
     * OAuth2 사용자 정보를 로드합니다.
     * Spring Security OAuth2 인증 과정에서 호출됩니다.
     *
     * @param userRequest OAuth2 로그인 요청 정보
     * @return OAuth2User 인증된 사용자 정보
     * @throws OAuth2AuthenticationException OAuth2 인증 과정에서 오류 발생 시
     */
    OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException;
    
    /**
     * OAuth2 사용자 정보를 바탕으로 사용자를 생성하거나 업데이트합니다.
     *
     * @param userInfo OAuth2 제공자로부터 받은 사용자 정보
     * @return 생성 또는 업데이트된 사용자 엔티티
     */
    User processOAuth2User(OAuth2UserInfoDto userInfo);
}
