package com.jinforce.backend.service;

import com.jinforce.backend.dto.OAuth2UserInfoDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    
    @Value("#{'${admin.emails}'.split(',')}")
    private List<String> adminEmails;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        User.AuthProvider provider = getProvider(registrationId);

        OAuth2UserInfoDto userInfo = OAuth2UserInfoDto.of(provider, oAuth2User.getAttributes());
        
        // 관리자 이메일 목록 로깅
        logAdminEmails();
        log.info("User login: {}, checking if admin...", userInfo.getEmail());
        log.info("Is admin: {}", isAdminEmail(userInfo.getEmail()));

        User user = processOAuth2User(userInfo);

        Map<String, Object> attributes = oAuth2User.getAttributes();

        return new DefaultOAuth2User(
                Collections.emptyList(),
                attributes,
                "email"
        );
    }

    private User.AuthProvider getProvider(String registrationId) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return User.AuthProvider.GOOGLE;
        }
        throw new IllegalArgumentException("Unsupported provider: " + registrationId);
    }

    /**
     * OAuth2 인증 정보로 사용자를 조회하거나 생성
     *
     * @param userInfo OAuth2 사용자 정보
     * @return User 엔티티
     */
    @Transactional
    public User processOAuth2User(OAuth2UserInfoDto userInfo) {
        return userRepository.findByEmail(userInfo.getEmail())
                .map(existingUser -> updateExistingUser(existingUser, userInfo))
                .orElseGet(() -> registerNewUser(userInfo));
    }

    /**
     * 기존 사용자 정보 업데이트
     *
     * @param existingUser 기존 사용자 엔티티
     * @param userInfo OAuth2 사용자 정보
     * @return 업데이트된 사용자 엔티티
     */
    private User updateExistingUser(User existingUser, OAuth2UserInfoDto userInfo) {
        existingUser.setName(userInfo.getName());
        existingUser.setImageUrl(userInfo.getImageUrl());
        
        // 관리자 이메일 확인 및 권한 업데이트
        if (isAdminEmail(userInfo.getEmail()) && !existingUser.isAdmin()) {
            existingUser.addAdminRole();
        }
        
        return userRepository.save(existingUser);
    }

    /**
     * 새 사용자 등록
     *
     * @param userInfo OAuth2 사용자 정보
     * @return 새로 생성된 사용자 엔티티
     */
    private User registerNewUser(OAuth2UserInfoDto userInfo) {
        User user = User.builder()
                .email(userInfo.getEmail())
                .name(userInfo.getName())
                .imageUrl(userInfo.getImageUrl())
                .provider(userInfo.getProvider())
                .providerId(userInfo.getId())
                .build();  // User 엔티티의 @PrePersist가 기본 ROLE_USER 권한을 추가함
        
        // 관리자 이메일이면 관리자 권한 추가
        if (isAdminEmail(userInfo.getEmail())) {
            user.addAdminRole();
        }
        
        return userRepository.save(user);
    }
    
    /**
     * 이메일이 관리자 이메일 목록에 포함되어 있는지 확인
     *
     * @param email 확인할 이메일
     * @return 관리자 이메일 여부
     */
    private boolean isAdminEmail(String email) {
        return adminEmails != null && adminEmails.contains(email);
    }
    
    /**
     * 테스트용: 사용자에게 관리자 권한 추가
     *
     * @param email 사용자 이메일
     * @return 업데이트된 사용자 엔티티
     */
    @Transactional
    public User addAdminRole(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + email));
        
        user.addAdminRole();
        return userRepository.save(user);
    }

    // 로깅 메서드 추가
    private void logAdminEmails() {
        log.info("Admin emails loaded: {}", adminEmails);
    }
}
