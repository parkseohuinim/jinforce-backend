package com.jinforce.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 이메일 기반 요청 DTO
 * 비밀번호 재설정 이메일 요청 등에 사용
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailRequestDto {
    private String email;
} 