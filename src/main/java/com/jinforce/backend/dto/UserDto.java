package com.jinforce.backend.dto;

import com.jinforce.backend.entity.User;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Schema(description = "사용자 정보 DTO")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    @Schema(description = "사용자 ID", example = "1")
    private Long id;
    
    @Schema(description = "이메일 주소", example = "user@example.com")
    private String email;
    
    @Schema(description = "사용자 이름", example = "홍길동")
    private String name;
    
    @Schema(description = "프로필 이미지 URL", example = "https://lh3.googleusercontent.com/a/profile-image")
    private String imageUrl;
    
    @Schema(description = "인증 제공자", example = "GOOGLE")
    private User.AuthProvider provider;
    
    @Schema(description = "사용자 역할 목록", example = "[\"USER\", \"ADMIN\"]")
    private List<User.Role> roles;

    public static UserDto fromEntity(User user) {
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .imageUrl(user.getImageUrl())
                .provider(user.getProvider())
                .roles(user.getRoles())
                .build();
    }
}
