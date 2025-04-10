package com.jinforce.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 회원가입 요청 DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequestDto {
    private String email;
    private String name;
    private String password;
} 