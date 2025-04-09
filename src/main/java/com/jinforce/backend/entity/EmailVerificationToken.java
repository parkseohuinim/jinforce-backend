package com.jinforce.backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "email_verification_tokens", schema = "jinforce_schema")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Column(nullable = false)
    private boolean confirmed;

    @Column(nullable = false)
    private String tokenType; // EMAIL_VERIFICATION, PASSWORD_RESET

    @Column
    private LocalDateTime confirmedAt;

    @Column(columnDefinition = "TEXT")
    private String metadata; // 추가 정보 저장용 JSON 문자열
    
    @Column(length = 6)
    private String otp; // 비밀번호 재설정용 6자리 OTP

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }
} 