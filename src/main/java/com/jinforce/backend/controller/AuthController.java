package com.jinforce.backend.controller;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/google")
    public ResponseEntity<TokenDto> authenticateWithGoogle(
            @RequestBody TokenDto.GoogleTokenInfo tokenInfo) {
        TokenDto token = authService.authenticateWithGoogle(tokenInfo);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenDto> refreshToken(
            @RequestBody TokenDto.Request request) {
        TokenDto token = authService.refreshToken(request.getToken());
        return ResponseEntity.ok(token);
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = authService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody TokenDto.Request request) {
        authService.logout(request.getToken());
        return ResponseEntity.ok().build();
    }
}