package com.jinforce.backend.service;

public interface EmailService {

    void sendVerificationEmail(String to, String token);
    void sendPasswordResetEmailWithOtp(String to, String otp);
} 