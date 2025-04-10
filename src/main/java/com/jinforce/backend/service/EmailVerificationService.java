package com.jinforce.backend.service;

import com.jinforce.backend.dto.TokenDto;

public interface EmailVerificationService {

    void createPasswordResetOtp(String email);
    void resetPasswordWithOtp(String email, String otp, String newPassword);
    TokenDto verifyEmailAndRegisterUser(String token);
    String createEmailVerificationTokenWithUserInfo(String email, String name, String password);
}