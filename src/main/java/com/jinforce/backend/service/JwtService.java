package com.jinforce.backend.service;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.entity.RefreshToken;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.exception.TokenException;
import com.jinforce.backend.repository.RefreshTokenRepository;
import com.jinforce.backend.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * JWT 토큰 관리 서비스
 * 액세스 토큰 및 리프레시 토큰 생성, 검증, 갱신 처리
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final UserDetailsService userDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidityInMilliseconds;

    @Value("${jwt.refresh-token-validity}")
    private long refreshTokenValidityInMilliseconds;

    /**
     * JWT 서명 키 생성
     */
    private Key getSigningKey() {
        byte[] keyBytes = secretKey.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 인증 객체로부터 액세스 토큰과 리프레시 토큰 생성
     */
    public TokenDto generateTokens(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = System.currentTimeMillis();
        Date accessTokenExpiry = new Date(now + accessTokenValidityInMilliseconds);

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setIssuedAt(new Date(now))
                .setExpiration(accessTokenExpiry)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = createRefreshToken(authentication.getName());

        return TokenDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(accessTokenValidityInMilliseconds / 1000)
                .build();
    }

    /**
     * 리프레시 토큰 생성 및 저장
     * 기존 토큰이 있으면 갱신, 없으면 새로 생성
     */
    @Transactional
    public String createRefreshToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new TokenException("사용자를 찾을 수 없습니다"));

        long now = System.currentTimeMillis();
        Date refreshTokenExpiry = new Date(now + refreshTokenValidityInMilliseconds);

        String refreshToken = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(now))
                .setExpiration(refreshTokenExpiry)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

        refreshTokenRepository.findByUser(user)
                .ifPresentOrElse(token -> {
                    token.setToken(refreshToken);
                    token.setExpiryDate(LocalDateTime.ofInstant(refreshTokenExpiry.toInstant(), ZoneId.systemDefault()));
                }, () -> {
                    RefreshToken token = RefreshToken.builder()
                            .user(user)
                            .token(refreshToken)
                            .expiryDate(LocalDateTime.ofInstant(refreshTokenExpiry.toInstant(), ZoneId.systemDefault()))
                            .build();
                    refreshTokenRepository.save(token);
                });

        return refreshToken;
    }

    /**
     * 리프레시 토큰을 사용하여 새 토큰 발급
     * 기존 리프레시 토큰은 무효화하고 새 리프레시 토큰 발급 (토큰 순환)
     */
    @Transactional
    public TokenDto refreshToken(String refreshToken) {
        validateToken(refreshToken);

        String email = extractEmail(refreshToken);
        RefreshToken savedRefreshToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new TokenException("유효하지 않은 리프레시 토큰입니다"));

        if (savedRefreshToken.isExpired()) {
            refreshTokenRepository.delete(savedRefreshToken);
            throw new TokenException("만료된 리프레시 토큰입니다");
        }

        // 토큰 재사용 감지 - DB에서 리프레시 토큰 삭제
        refreshTokenRepository.delete(savedRefreshToken);
        
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        // 새 토큰 발급 (새 리프레시 토큰 포함)
        return generateTokens(authentication);
    }

    /**
     * JWT 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            log.error("유효하지 않은 JWT 서명");
            throw new TokenException("유효하지 않은 JWT 서명");
        } catch (MalformedJwtException ex) {
            log.error("잘못된 형식의 JWT 토큰");
            throw new TokenException("잘못된 형식의 JWT 토큰");
        } catch (ExpiredJwtException ex) {
            log.error("만료된 JWT 토큰");
            throw new TokenException("만료된 JWT 토큰");
        } catch (UnsupportedJwtException ex) {
            log.error("지원되지 않는 JWT 토큰");
            throw new TokenException("지원되지 않는 JWT 토큰");
        } catch (IllegalArgumentException ex) {
            log.error("JWT 클레임이 비어있음");
            throw new TokenException("JWT 클레임이 비어있음");
        }
    }

    /**
     * 토큰에서 이메일 추출
     */
    public String extractEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * 토큰으로부터 인증 객체 생성
     */
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .filter(auth -> !auth.trim().isEmpty())
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails userDetails = userDetailsService.loadUserByUsername(claims.getSubject());

        return new UsernamePasswordAuthenticationToken(userDetails, token, authorities);
    }

    /**
     * 리프레시 토큰 무효화
     */
    @Transactional
    public void invalidateRefreshToken(User user) {
        refreshTokenRepository.findByUser(user)
                .ifPresent(refreshTokenRepository::delete);
    }

    /**
     * 테스트용 짧은 만료 시간을 가진 액세스 토큰 생성
     * 토큰 만료 테스트에 사용됨
     *
     * @param authentication 인증 객체
     * @param expirationMillis 만료 시간 (밀리초)
     * @return 생성된 액세스 토큰
     */
    public String generateTokenWithCustomExpiry(Authentication authentication, long expirationMillis) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = System.currentTimeMillis();
        Date accessTokenExpiry = new Date(now + expirationMillis);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setIssuedAt(new Date(now))
                .setExpiration(accessTokenExpiry)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}