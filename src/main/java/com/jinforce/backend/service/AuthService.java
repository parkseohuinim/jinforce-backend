package com.jinforce.backend.service;

import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;

public interface AuthService {

    TokenDto authenticateWithGoogle(TokenDto.GoogleAuthRequest authRequest);
    TokenDto refreshToken(String refreshToken);
    UserDto getCurrentUser();
    void logout(String refreshToken);
    TokenDto login(String email, String password);
}
