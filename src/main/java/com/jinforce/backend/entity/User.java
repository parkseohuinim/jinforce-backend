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

    // 비밀번호 (로컬 로그인용)
    private String password;

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
    @Column(name = "roles")
    @Builder.Default
    private List<Role> roles = new ArrayList<>();

    // 레코드 생성 시간 (자동 기록)
    @CreatedDate
    private LocalDateTime createdAt;

    // 레코드 마지막 수정 시간 (자동 기록)
    @LastModifiedDate
    private LocalDateTime updatedAt;

    /**
     * 사용자 생성 시 기본 권한(ROLE_USER)을 설정합니다.
     */
    @PrePersist
    protected void onCreate() {
        if (roles == null) {
            roles = new ArrayList<>();
        }
        
        if (roles.isEmpty()) {
            roles.add(Role.ROLE_USER);
        }
    }

    /**
     * 관리자 권한을 추가합니다.
     * 이미 관리자 권한이 있는 경우 아무 작업도 하지 않습니다.
     */
    public void addAdminRole() {
        if (roles == null) {
            roles = new ArrayList<>();
        }
        
        if (!hasRole(Role.ROLE_ADMIN)) {
            roles.add(Role.ROLE_ADMIN);
        }
    }

    /**
     * 지정된 권한이 있는지 확인합니다.
     */
    public boolean hasRole(Role role) {
        return roles != null && roles.contains(role);
    }

    /**
     * 관리자 권한이 있는지 확인합니다.
     */
    public boolean isAdmin() {
        return hasRole(Role.ROLE_ADMIN);
    }

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
