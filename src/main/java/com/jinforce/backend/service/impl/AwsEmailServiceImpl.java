package com.jinforce.backend.service.impl;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.model.*;
import com.jinforce.backend.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AwsEmailServiceImpl implements EmailService {

    private final AmazonSimpleEmailService amazonSES;

    @Value("${aws.ses.sender-email}")
    private String senderEmail;

    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Value("${server.port}")
    private String serverPort;

    @Override
    public void sendVerificationEmail(String to, String token) {
        String subject = "진포스 - 이메일 주소 인증";
        String verificationUrl = String.format("http://localhost:%s%s/auth/register/verify?token=%s", 
                                serverPort, contextPath, token);
        
        String htmlBody = String.format(
            "<html>" +
            "<body style='font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333;'>" +
            "<div style='max-width: 600px; margin: 0 auto; background-color: #fff; border: 1px solid #e9e9e9; border-radius: 5px; overflow: hidden;'>" +
            "<div style='background-color: #4A69BD; padding: 20px; text-align: center;'>" +
            "<h1 style='color: white; margin: 0;'>진포스 이메일 인증</h1>" +
            "</div>" +
            "<div style='padding: 20px;'>" +
            "<p>안녕하세요,</p>" +
            "<p>진포스 서비스 가입을 위한 이메일 인증 절차입니다.</p>" +
            "<p>아래 버튼을 클릭하여 인증을 완료해주세요:</p>" +
            "<div style='text-align: center; margin: 30px 0;'>" +
            "<a href='%s' style='background-color: #4A69BD; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;'>이메일 인증하기</a>" +
            "</div>" +
            "<p>또는 다음 링크를 브라우저에 복사하여 접속해주세요:</p>" +
            "<p style='word-break: break-all;'><a href='%s'>%s</a></p>" +
            "<p>이 링크는 24시간 동안 유효합니다.</p>" +
            "<p>감사합니다,<br/>진포스 팀</p>" +
            "</div>" +
            "</div>" +
            "</body>" +
            "</html>", verificationUrl, verificationUrl, verificationUrl);

        sendEmail(to, subject, htmlBody);
    }

    @Override
    public void sendPasswordResetEmailWithOtp(String to, String otp) {
        String subject = "진포스 - 비밀번호 재설정 인증번호";
        
        String htmlBody = String.format(
            "<html>" +
            "<body style='font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333;'>" +
            "<div style='max-width: 600px; margin: 0 auto; background-color: #fff; border: 1px solid #e9e9e9; border-radius: 5px; overflow: hidden;'>" +
            "<div style='background-color: #4A69BD; padding: 20px; text-align: center;'>" +
            "<h1 style='color: white; margin: 0;'>진포스 비밀번호 재설정</h1>" +
            "</div>" +
            "<div style='padding: 20px;'>" +
            "<p>안녕하세요,</p>" +
            "<p>비밀번호 재설정을 위한 인증 코드입니다:</p>" +
            "<div style='text-align: center; margin: 30px 0;'>" +
            "<div style='background-color: #f5f5f5; padding: 15px; font-size: 24px; letter-spacing: 5px; font-weight: bold;'>%s</div>" +
            "</div>" +
            "<p>이 코드는 10분 동안 유효합니다.</p>" +
            "<p>본인이 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.</p>" +
            "<p>감사합니다,<br/>진포스 팀</p>" +
            "</div>" +
            "</div>" +
            "</body>" +
            "</html>", otp);

        sendEmail(to, subject, htmlBody);
    }

    private void sendEmail(String to, String subject, String htmlBody) {
        try {
            SendEmailRequest request = new SendEmailRequest()
                .withDestination(new Destination().withToAddresses(to))
                .withMessage(new Message()
                    .withBody(new Body()
                        .withHtml(new Content()
                            .withCharset("UTF-8").withData(htmlBody)))
                    .withSubject(new Content()
                        .withCharset("UTF-8").withData(subject)))
                .withSource(senderEmail);

            amazonSES.sendEmail(request);
            log.info("Email sent successfully to {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Failed to send email", e);
        }
    }
} 