package com.jinforce.backend.controller;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/resources")
@RequiredArgsConstructor
public class ResourceController {

    private final AuthService authService;

    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> getPublicResource() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a public resource");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> getUserResource() {
        UserDto userDto = authService.getCurrentUser();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a protected user resource");
        response.put("user", userDto);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> getAdminResource() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a protected admin resource");
        return ResponseEntity.ok(response);
    }
}
