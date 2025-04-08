package com.jinforce.backend.controller;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.repository.UserRepository;
import com.jinforce.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 보호된 리소스 접근 컨트롤러
 * 일반 사용자와 관리자 권한에 따른 API 제공
 */
@RestController
@RequestMapping("/resources")
@RequiredArgsConstructor
public class ResourceController {

    private final AuthService authService;
    private final UserRepository userRepository;

    /**
     * 공개 리소스 API
     * 인증 없이 접근 가능
     */
    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> getPublicResource() {
        return ResponseEntity.ok(Map.of("message", "This is a public resource"));
    }

    /**
     * 보호된 리소스 API
     * 로그인한 모든 사용자 접근 가능
     */
    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> getProtectedResource() {
        return ResponseEntity.ok(Map.of("message", "This is a protected resource"));
    }

    /**
     * 관리자 전용 API - 사용자 목록 조회
     * ROLE_ADMIN 권한을 가진 사용자만 접근 가능
     */
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        List<UserDto> users = userRepository.findAll().stream()
                .map(UserDto::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
    }

    /**
     * 관리자 전용 API - 시스템 통계 조회
     * ROLE_ADMIN 권한을 가진 사용자만 접근 가능
     */
    @GetMapping("/admin/stats")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<Map<String, Object>> getSystemStats() {
        long userCount = userRepository.count();
        long adminCount = userRepository.findAll().stream()
                .filter(user -> user.getRoles().contains(User.Role.ROLE_ADMIN))
                .count();
        
        return ResponseEntity.ok(Map.of(
                "totalUsers", userCount,
                "adminUsers", adminCount,
                "systemVersion", "1.0.0",
                "lastUpdated", System.currentTimeMillis()
        ));
    }
}
