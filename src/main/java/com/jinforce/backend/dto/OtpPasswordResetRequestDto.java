package com.jinforce.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * OTP를 사용한 비밀번호 재설정 요청 DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpPasswordResetRequestDto {
    private String email;
    private String otp;
    private String password;
} 