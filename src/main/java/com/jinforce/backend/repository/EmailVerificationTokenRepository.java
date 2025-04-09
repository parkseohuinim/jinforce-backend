package com.jinforce.backend.repository;

import com.jinforce.backend.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    Optional<EmailVerificationToken> findByToken(String token);

    Optional<EmailVerificationToken> findByEmailAndTokenType(String email, String tokenType);
    
    Optional<EmailVerificationToken> findByEmailAndTokenTypeAndOtp(String email, String tokenType, String otp);

    List<EmailVerificationToken> findAllByExpiryDateBeforeAndConfirmed(LocalDateTime now, boolean confirmed);

    boolean existsByEmailAndTokenTypeAndConfirmed(String email, String tokenType, boolean confirmed);
} 