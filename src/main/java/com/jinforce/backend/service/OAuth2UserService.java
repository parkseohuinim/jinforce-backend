package com.jinforce.backend.service;

import com.jinforce.backend.dto.OAuth2UserInfoDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        User.AuthProvider provider = getProvider(registrationId);

        OAuth2UserInfoDto userInfo = OAuth2UserInfoDto.of(provider, oAuth2User.getAttributes());

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

    @Transactional
    public User processOAuth2User(OAuth2UserInfoDto userInfo) {
        // Check if user already exists
        return userRepository.findByEmail(userInfo.getEmail())
                .map(existingUser -> updateExistingUser(existingUser, userInfo))
                .orElseGet(() -> registerNewUser(userInfo));
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfoDto userInfo) {
        existingUser.setName(userInfo.getName());
        existingUser.setImageUrl(userInfo.getImageUrl());
        return userRepository.save(existingUser);
    }

    private User registerNewUser(OAuth2UserInfoDto userInfo) {
        User user = User.builder()
                .email(userInfo.getEmail())
                .name(userInfo.getName())
                .imageUrl(userInfo.getImageUrl())
                .provider(userInfo.getProvider())
                .providerId(userInfo.getId())
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        return userRepository.save(user);
    }
}
