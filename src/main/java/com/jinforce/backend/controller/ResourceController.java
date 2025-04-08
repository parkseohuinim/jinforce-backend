package com.jinforce.backend.controller;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.repository.UserRepository;
import com.jinforce.backend.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 보호된 리소스 접근 컨트롤러
 * 일반 사용자와 관리자 권한에 따른 API 제공
 */
@Tag(name = "Resources", description = "리소스 및 관리자 기능 API")
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
    @Operation(
        summary = "공개 리소스 조회", 
        description = "인증 없이 누구나 접근 가능한 공개 리소스를 제공합니다"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "조회 성공")
    })
    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> getPublicResource() {
        return ResponseEntity.ok(Map.of("message", "This is a public resource"));
    }

    /**
     * 보호된 리소스 API
     * 로그인한 모든 사용자 접근 가능
     */
    @Operation(
        summary = "보호된 리소스 조회", 
        description = "로그인한 사용자만 접근 가능한 리소스를 제공합니다"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "조회 성공"), 
        @ApiResponse(responseCode = "401", description = "인증 필요")
    })
    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> getProtectedResource() {
        return ResponseEntity.ok(Map.of("message", "This is a protected resource"));
    }

    /**
     * 관리자 전용 API - 사용자 목록 조회
     * ROLE_ADMIN 권한을 가진 사용자만 접근 가능
     */
    @Operation(
        summary = "사용자 목록 조회", 
        description = "시스템에 등록된 모든 사용자 목록을 조회합니다. 관리자만 접근 가능합니다."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "조회 성공",
                content = @Content(
                    mediaType = "application/json",
                    array = @io.swagger.v3.oas.annotations.media.ArraySchema(
                        schema = @Schema(implementation = UserDto.class)
                    )
                )),
        @ApiResponse(responseCode = "403", description = "권한 없음"),
        @ApiResponse(responseCode = "401", description = "인증 필요")
    })
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
    @Operation(
        summary = "시스템 통계 조회", 
        description = "사용자 통계와 시스템 정보를 조회합니다. 관리자만 접근 가능합니다."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "조회 성공"),
        @ApiResponse(responseCode = "403", description = "권한 없음"),
        @ApiResponse(responseCode = "401", description = "인증 필요")
    })
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
    
    /**
     * 관리자 권한 추가 API
     * 특정 이메일의 사용자에게 관리자 권한을 추가
     */
    @Operation(
        summary = "관리자 권한 추가", 
        description = "특정 이메일의 사용자에게 관리자 권한을 추가합니다. 인증 없이 누구나 접근 가능합니다."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "권한 추가 성공",
                content = @Content(schema = @Schema(implementation = UserDto.class))),
        @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음")
    })
    @PostMapping("/add-admin/{email}")
    @Transactional
    public ResponseEntity<UserDto> addAdminRole(
            @Parameter(description = "관리자 권한을 추가할 사용자의 이메일", required = true)
            @PathVariable String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다: " + email));
        
        if (!user.getRoles().contains(User.Role.ROLE_ADMIN)) {
            user.getRoles().add(User.Role.ROLE_ADMIN);
            userRepository.save(user);
        }
        
        return ResponseEntity.ok(UserDto.fromEntity(user));
    }
}
