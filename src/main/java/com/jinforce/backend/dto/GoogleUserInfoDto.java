package com.jinforce.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GoogleUserInfoDto {

    private String sub;
    private String name;
    private String givenName;
    private String familyName;
    private String picture;
    private String email;
    private Boolean emailVerified;
    private String locale;

    /**
     * GoogleUserInfoDto를 속성 맵으로 변환합니다.
     *
     * @return OAuth2User 형식에 맞는 속성 맵
     */
    public Map<String, Object> toAttributeMap() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", sub);
        attributes.put("name", name);
        attributes.put("given_name", givenName);
        attributes.put("family_name", familyName);
        attributes.put("picture", picture);
        attributes.put("email", email);
        attributes.put("email_verified", emailVerified);
        attributes.put("locale", locale);
        return attributes;
    }
}
