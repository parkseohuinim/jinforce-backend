package com.jinforce.backend.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * 리프레시 토큰 엔티티
 * 사용자의 리프레시 토큰 정보를 저장하고 관리
 * AuditingEntityListener를 통해 생성/수정 시간 자동 관리
 */
@Entity
@Table(name = "refresh_tokens", schema = "jinforce_schema")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 리프레시 토큰 문자열 (고유값)
    @Column(nullable = false, unique = true)
    private String token;

    // 토큰 소유자
    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // 토큰 만료 시간
    @Column(nullable = false)
    private LocalDateTime expiryDate;

    // 레코드 생성 시간 (자동 기록)
    @CreatedDate
    private LocalDateTime createdAt;

    // 레코드 마지막 수정 시간 (자동 기록)
    @LastModifiedDate
    private LocalDateTime updatedAt;

    /**
     * 토큰 만료 여부 확인
     * 현재 시간이 만료 시간 이후인지 검사
     * @return 만료 여부
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }
}
