package com.jinforce.backend.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * 사용자 정보를 저장하는 엔티티 클래스
 * 소셜 로그인 정보와 사용자 권한을 관리하며, 생성/수정 시간 자동 기록
 */
@Entity
@Table(name = "users", schema = "jinforce_schema")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 사용자 이메일 (고유값)
    @Column(unique = true, nullable = false)
    private String email;

    // 사용자 이름
    private String name;

    // 프로필 이미지 URL
    private String imageUrl;

    // 인증 제공자 (GOOGLE, FACEBOOK 등)
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    // 제공자에서의 사용자 ID
    private String providerId;

    // 사용자 권한 목록 (ROLE_USER, ROLE_ADMIN)
    @Enumerated(EnumType.STRING)
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_roles",
            schema = "jinforce_schema",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Builder.Default
    private List<Role> roles = new ArrayList<>();

    // 레코드 생성 시간 (자동 기록)
    @CreatedDate
    private LocalDateTime createdAt;

    // 레코드 마지막 수정 시간 (자동 기록)
    @LastModifiedDate
    private LocalDateTime updatedAt;

    /**
     * 지원하는 인증 제공자 유형
     */
    public enum AuthProvider {
        GOOGLE, FACEBOOK, GITHUB, LOCAL
    }

    /**
     * 사용자 권한 유형
     */
    public enum Role {
        ROLE_USER, ROLE_ADMIN
    }
}
