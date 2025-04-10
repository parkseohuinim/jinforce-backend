package com.jinforce.backend.controller;

import com.jinforce.backend.dto.EmailRequestDto;
import com.jinforce.backend.dto.OtpPasswordResetRequestDto;
import com.jinforce.backend.dto.SignupRequestDto;
import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.service.EmailVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Tag(name = "Registration", description = "회원가입 및 계정 관리 API")
@RestController
@RequestMapping("/auth/register")
@RequiredArgsConstructor
public class RegisterController {

    private final EmailVerificationService emailVerificationService;

    @Operation(summary = "이메일 회원가입 요청", description = "이메일로 회원가입을 시작하고 인증 이메일을 발송합니다.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "회원가입 요청 및 이메일 발송 성공"),
        @ApiResponse(responseCode = "400", description = "잘못된 요청"),
        @ApiResponse(responseCode = "409", description = "이미 등록된 이메일")
    })
    @PostMapping("")
    public ResponseEntity<Map<String, String>> signupWithEmail(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "회원가입 정보", 
                required = true, 
                content = @Content(schema = @Schema(implementation = SignupRequestDto.class))
            )
            @RequestBody SignupRequestDto request) {
        // 이메일 인증 토큰 생성 및 이메일 발송
        String token = emailVerificationService.createEmailVerificationTokenWithUserInfo(
                request.getEmail(), 
                request.getName(), 
                request.getPassword()
        );
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "가입을 위한 인증 이메일이 발송되었습니다. 이메일을 확인해주세요.");
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "이메일 인증 확인 및 회원가입 완료", description = "이메일 인증 토큰을 확인하고 회원가입을 완료합니다.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "인증 및 회원가입 성공, JWT 토큰 발급", 
                     content = @Content(schema = @Schema(implementation = TokenDto.class))),
        @ApiResponse(responseCode = "400", description = "유효하지 않은 토큰")
    })
    @GetMapping("/verify")
    public ResponseEntity<?> verifyEmailAndComplete(@RequestParam String token) {
        try {
            // 이메일 인증 확인 및 회원가입 완료 (JWT 토큰 발급)
            TokenDto tokenDto = emailVerificationService.verifyEmailAndRegisterUser(token);
            
            // JWT 토큰 반환
            return ResponseEntity.ok(tokenDto);
        } catch (Exception e) {
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @Operation(summary = "비밀번호 재설정 OTP 요청", description = "비밀번호 재설정을 위한 인증 코드를 이메일로 발송합니다.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "이메일 발송 성공"),
        @ApiResponse(responseCode = "400", description = "등록되지 않은 이메일")
    })
    @PostMapping("/password/request-otp")
    public ResponseEntity<Map<String, String>> requestPasswordResetOtp(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "비밀번호 재설정 요청 이메일", 
                required = true, 
                content = @Content(schema = @Schema(implementation = EmailRequestDto.class))
            )
            @RequestBody EmailRequestDto request) {
        emailVerificationService.createPasswordResetOtp(request.getEmail());
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "비밀번호 재설정 인증 코드가 이메일로 발송되었습니다.");
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "OTP로 비밀번호 재설정", description = "인증 코드를 확인하고 비밀번호를 재설정합니다.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "비밀번호 재설정 성공"),
        @ApiResponse(responseCode = "400", description = "유효하지 않은 인증 코드 또는 요청")
    })
    @PostMapping("/password/reset-with-otp")
    public ResponseEntity<Map<String, String>> resetPasswordWithOtp(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "비밀번호 재설정 정보", 
                required = true, 
                content = @Content(schema = @Schema(implementation = OtpPasswordResetRequestDto.class))
            )
            @RequestBody OtpPasswordResetRequestDto request) {
        emailVerificationService.resetPasswordWithOtp(
            request.getEmail(),
            request.getOtp(),
            request.getPassword()
        );
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "비밀번호가 성공적으로 재설정되었습니다.");
        return ResponseEntity.ok(response);
    }
} 