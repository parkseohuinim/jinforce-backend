package com.jinforce.backend.dto;

import com.jinforce.backend.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2UserInfoDto {

    private Map<String, Object> attributes;
    private String id;
    private String name;
    private String email;
    private String imageUrl;
    private User.AuthProvider provider;

    public static OAuth2UserInfoDto of(User.AuthProvider provider, Map<String, Object> attributes) {
        if (provider == User.AuthProvider.GOOGLE) {
            return ofGoogle(attributes);
        }
        throw new IllegalArgumentException("Unsupported provider: " + provider);
    }

    private static OAuth2UserInfoDto ofGoogle(Map<String, Object> attributes) {
        return OAuth2UserInfoDto.builder()
                .provider(User.AuthProvider.GOOGLE)
                .attributes(attributes)
                .id((String) attributes.get("sub"))
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .imageUrl((String) attributes.get("picture"))
                .build();
    }
}
