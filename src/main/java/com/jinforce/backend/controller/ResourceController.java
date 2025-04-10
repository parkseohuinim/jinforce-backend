package com.jinforce.backend.controller;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.repository.UserRepository;
import com.jinforce.backend.service.AuthService;
import com.jinforce.backend.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

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
    private final UserService userService;

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
        return ResponseEntity.ok(userService.getAllUsers());
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
        return ResponseEntity.ok(userService.getSystemStats());
    }
    
    /**
     * 관리자 권한 추가 API
     * 보안을 위해 인증 요구 및 기존 관리자 권한 필요
     */
    @Operation(
        summary = "관리자 권한 추가", 
        description = "특정 이메일의 사용자에게 관리자 권한을 추가합니다. 관리자만 접근 가능합니다."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "권한 추가 성공",
                content = @Content(schema = @Schema(implementation = UserDto.class))),
        @ApiResponse(responseCode = "404", description = "존재하지 않는 사용자 이메일"),
        @ApiResponse(responseCode = "409", description = "이미 관리자 권한을 가진 사용자"),
        @ApiResponse(responseCode = "403", description = "권한 없음"),
        @ApiResponse(responseCode = "401", description = "인증 필요")
    })
    @PostMapping("/admin/add-admin/{email}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<UserDto> addAdminRole(
            @Parameter(description = "관리자 권한을 추가할 사용자의 이메일", required = true)
            @PathVariable String email) {
        return ResponseEntity.ok(userService.addAdminRole(email));
    }
}
