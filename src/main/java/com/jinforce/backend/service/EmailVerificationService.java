package com.jinforce.backend.service;

import com.jinforce.backend.entity.EmailVerificationToken;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.exception.TokenException;
import com.jinforce.backend.exception.UserException;
import com.jinforce.backend.repository.EmailVerificationTokenRepository;
import com.jinforce.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${token.email-verification.expiration-minutes:1440}") // 24시간
    private int emailVerificationTokenExpirationMinutes;

    @Value("${token.password-reset.expiration-minutes:60}") // 1시간
    private int passwordResetTokenExpirationMinutes;

    public static final String EMAIL_VERIFICATION = "EMAIL_VERIFICATION";
    public static final String PASSWORD_RESET = "PASSWORD_RESET";

    /**
     * 이메일 인증 요청을 처리하고 인증 이메일을 발송합니다.
     * 
     * @param email 인증 대상 이메일
     * @return 생성된 토큰
     */
    @Transactional
    public String createEmailVerificationToken(String email) {
        // 이미 인증된 이메일인지 확인
        if (userRepository.existsByEmail(email)) {
            throw new UserException("이미 등록된 이메일입니다.");
        }

        // 기존 토큰이 있다면 삭제
        tokenRepository.findByEmailAndTokenType(email, EMAIL_VERIFICATION)
                .ifPresent(tokenRepository::delete);

        // 새 토큰 생성
        String token = UUID.randomUUID().toString();
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .email(email)
                .token(token)
                .tokenType(EMAIL_VERIFICATION)
                .confirmed(false)
                .expiryDate(LocalDateTime.now().plusMinutes(emailVerificationTokenExpirationMinutes))
                .build();

        tokenRepository.save(verificationToken);
        
        // 인증 이메일 발송
        emailService.sendVerificationEmail(email, token);
        
        return token;
    }

    /**
     * 비밀번호 재설정을 위한 6자리 OTP 코드를 생성하고 이메일로 발송합니다.
     * 
     * @param email 대상 이메일
     */
    @Transactional
    public void createPasswordResetOtp(String email) {
        // 사용자 이메일 확인
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserException("등록되지 않은 이메일입니다."));

        // 소셜 로그인으로 가입한 사용자인지 확인
        if (user.getProvider() != null && user.getProvider() != User.AuthProvider.LOCAL) {
            throw new UserException(user.getProvider().name() + " 계정으로 가입한 사용자는 비밀번호 재설정이 불가능합니다. " 
                    + user.getProvider().name() + " 로그인을 이용해주세요.");
        }

        // 기존의 유효한 OTP가 있으면 삭제
        tokenRepository.findByEmailAndTokenType(email, PASSWORD_RESET)
                .ifPresent(tokenRepository::delete);

        // 6자리 OTP 생성
        String otp = generateRandomOtp();
        
        // 토큰 생성 및 저장
        EmailVerificationToken token = EmailVerificationToken.builder()
                .email(email)
                .token(UUID.randomUUID().toString())
                .otp(otp)
                .tokenType(PASSWORD_RESET)
                .expiryDate(LocalDateTime.now().plusMinutes(passwordResetTokenExpirationMinutes))
                .confirmed(false)
                .build();
        tokenRepository.save(token);

        // 이메일 발송
        emailService.sendPasswordResetEmailWithOtp(email, otp);
    }

    /**
     * OTP를 검증하고 비밀번호를 재설정합니다.
     * 
     * @param email 사용자 이메일
     * @param otp 입력받은 OTP
     * @param newPassword 새 비밀번호
     */
    @Transactional
    public void resetPasswordWithOtp(String email, String otp, String newPassword) {
        // OTP 검증
        EmailVerificationToken token = tokenRepository
                .findByEmailAndTokenTypeAndOtp(email, PASSWORD_RESET, otp)
                .orElseThrow(() -> new TokenException("유효하지 않은 인증 코드입니다."));

        // 토큰 만료 확인
        if (token.isExpired()) {
            throw new TokenException("만료된 인증 코드입니다.");
        }
        
        if (token.isConfirmed()) {
            throw new TokenException("이미 사용된 인증 코드입니다.");
        }

        // 비밀번호 변경
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserException("사용자를 찾을 수 없습니다."));
        
        // 소셜 로그인으로 가입한 사용자인지 확인
        if (user.getProvider() != null && user.getProvider() != User.AuthProvider.LOCAL) {
            throw new UserException(user.getProvider().name() + " 계정으로 가입한 사용자는 비밀번호 재설정이 불가능합니다. " 
                    + user.getProvider().name() + " 로그인을 이용해주세요.");
        }
        
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // 토큰 사용 완료 처리
        token.setConfirmed(true);
        token.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(token);
        
        log.info("비밀번호가 성공적으로 재설정되었습니다. 이메일: {}", email);
    }

    /**
     * 이메일 인증 토큰을 검증하고 계정을 활성화합니다.
     * 
     * @param token 인증 토큰
     * @return 인증된 이메일
     */
    @Transactional
    public String verifyEmailToken(String token) {
        EmailVerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenException("유효하지 않은 토큰입니다."));

        if (!EMAIL_VERIFICATION.equals(verificationToken.getTokenType())) {
            throw new TokenException("유효하지 않은 토큰 유형입니다.");
        }

        if (verificationToken.isExpired()) {
            throw new TokenException("만료된 토큰입니다.");
        }

        if (verificationToken.isConfirmed()) {
            throw new TokenException("이미 사용된 토큰입니다.");
        }

        // 토큰 확인 처리
        verificationToken.setConfirmed(true);
        verificationToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(verificationToken);

        return verificationToken.getEmail();
    }

    /**
     * 비밀번호 재설정 토큰을 검증합니다.
     * 
     * @param token 재설정 토큰
     * @return 해당 이메일
     */
    @Transactional(readOnly = true)
    public String verifyPasswordResetToken(String token) {
        EmailVerificationToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenException("유효하지 않은 토큰입니다."));

        if (!PASSWORD_RESET.equals(resetToken.getTokenType())) {
            throw new TokenException("유효하지 않은 토큰 유형입니다.");
        }

        if (resetToken.isExpired()) {
            throw new TokenException("만료된 토큰입니다.");
        }

        if (resetToken.isConfirmed()) {
            throw new TokenException("이미 사용된 토큰입니다.");
        }

        return resetToken.getEmail();
    }

    /**
     * 비밀번호 재설정 토큰을 사용 완료로 처리합니다.
     * 
     * @param token 재설정 토큰
     */
    @Transactional
    public void confirmPasswordResetToken(String token) {
        EmailVerificationToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenException("유효하지 않은 토큰입니다."));

        resetToken.setConfirmed(true);
        resetToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(resetToken);
    }
    
    /**
     * 이메일 확인 후 JWT 토큰 발급 (사용자 등록 처리 포함)
     * 
     * @param token 인증 토큰
     * @param name 사용자 이름
     * @param password 패스워드 (암호화되어 저장)
     * @return JWT 토큰
     */
    @Transactional
    public com.jinforce.backend.dto.TokenDto verifyEmailAndRegisterUser(String token) {
        EmailVerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenException("유효하지 않은 토큰입니다."));

        if (!EMAIL_VERIFICATION.equals(verificationToken.getTokenType())) {
            throw new TokenException("유효하지 않은 토큰 유형입니다.");
        }

        if (verificationToken.isExpired()) {
            throw new TokenException("만료된 토큰입니다.");
        }

        if (verificationToken.isConfirmed()) {
            throw new TokenException("이미 사용된 토큰입니다.");
        }

        String email = verificationToken.getEmail();
        
        // 이미 해당 이메일로 가입된 사용자가 있는지 확인
        if (userRepository.existsByEmail(email)) {
            throw new UserException("이미 등록된 이메일입니다.");
        }
        
        // 토큰에서 저장된 사용자 정보 추출
        String metadata = verificationToken.getMetadata();
        String name = "사용자"; // 기본값
        String password = ""; // 기본값
        
        try {
            // 간단한 메타데이터 파싱 (실제로는 ObjectMapper 등을 사용하는 것이 좋음)
            if (metadata != null && !metadata.isEmpty()) {
                if (metadata.contains("name")) {
                    name = metadata.split("name\":\"")[1].split("\"")[0];
                }
                if (metadata.contains("password")) {
                    password = metadata.split("password\":\"")[1].split("\"")[0];
                }
            }
        } catch (Exception e) {
            log.warn("메타데이터 파싱 중 오류: {}", e.getMessage());
        }
        
        // 사용자 등록
        User user = User.builder()
                .email(email)
                .name(name)
                .password(password) // 이미 암호화된 비밀번호
                .provider(User.AuthProvider.LOCAL)
                .build();  // roles는 @PrePersist에서 자동으로 추가됨
        
        userRepository.save(user);
        
        // 토큰 사용 완료 처리
        verificationToken.setConfirmed(true);
        verificationToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(verificationToken);
        
        // JWT 토큰 발급
        Authentication authentication = createAuthentication(user);
        return jwtService.generateTokens(authentication);
    }

    /**
     * 사용자 엔티티로부터 Authentication 객체를 생성합니다.
     */
    private Authentication createAuthentication(User user) {
        var authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(
                user.getEmail(),
                null,
                authorities
        );
    }

    /**
     * 이메일 회원가입 요청을 처리하고 인증 이메일을 발송합니다.
     * 사용자 정보(이름, 비밀번호)를 임시 저장합니다.
     * 
     * @param email 인증 대상 이메일
     * @param name 사용자 이름
     * @param password 비밀번호 (암호화 필요)
     * @return 생성된 토큰
     */
    @Transactional
    public String createEmailVerificationTokenWithUserInfo(String email, String name, String password) {
        // 이미 인증된 이메일인지 확인
        if (userRepository.existsByEmail(email)) {
            throw new UserException("이미 등록된 이메일입니다.");
        }

        // 기존 토큰이 있다면 삭제
        tokenRepository.findByEmailAndTokenType(email, EMAIL_VERIFICATION)
                .ifPresent(tokenRepository::delete);

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(password);

        // 새 토큰 생성 - 사용자 정보를 토큰 설명에 저장
        String token = UUID.randomUUID().toString();
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .email(email)
                .token(token)
                .tokenType(EMAIL_VERIFICATION)
                .confirmed(false)
                .expiryDate(LocalDateTime.now().plusMinutes(emailVerificationTokenExpirationMinutes))
                // 사용자 정보를 토큰 엔티티에 임시 저장 (비밀번호는 이미 암호화됨)
                .metadata("{\"name\":\"" + name + "\", \"password\":\"" + encodedPassword + "\"}")
                .build();

        tokenRepository.save(verificationToken);
        
        // 인증 이메일 발송
        emailService.sendVerificationEmail(email, token);
        
        return token;
    }

    /**
     * 6자리 랜덤 OTP 생성
     */
    private String generateRandomOtp() {
        // 6자리 숫자 생성: 100000-999999
        int randomNumber = 100000 + (int)(Math.random() * 900000);
        return String.valueOf(randomNumber);
    }
} 