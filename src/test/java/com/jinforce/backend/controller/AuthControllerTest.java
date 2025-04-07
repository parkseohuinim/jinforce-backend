package com.jinforce.backend.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jinforce.backend.dto.TokenDto;
import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    @org.junit.jupiter.api.BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void authenticateWithGoogle_ShouldReturnTokenDto() throws Exception {
        // Given
        TokenDto.GoogleTokenInfo googleTokenInfo = new TokenDto.GoogleTokenInfo();
        googleTokenInfo.setIdToken("id-token-value");
        googleTokenInfo.setAccessToken("access-token-value");

        TokenDto expectedTokenDto = TokenDto.builder()
                .accessToken("jwt-access-token")
                .refreshToken("jwt-refresh-token")
                .tokenType("Bearer")
                .expiresIn(3600L)
                .build();

        when(authService.authenticateWithGoogle(any(TokenDto.GoogleTokenInfo.class))).thenReturn(expectedTokenDto);

        // When & Then
        mockMvc.perform(post("/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(googleTokenInfo)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("jwt-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("jwt-refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(3600));
    }

    @Test
    void refreshToken_ShouldReturnNewTokenDto() throws Exception {
        // Given
        TokenDto.Request request = new TokenDto.Request();
        request.setToken("refresh-token-value");

        TokenDto expectedTokenDto = TokenDto.builder()
                .accessToken("new-jwt-access-token")
                .refreshToken("new-jwt-refresh-token")
                .tokenType("Bearer")
                .expiresIn(3600L)
                .build();

        when(authService.refreshToken(any(String.class))).thenReturn(expectedTokenDto);

        // When & Then
        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-jwt-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-jwt-refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(3600));
    }

    @Test
    @WithMockUser
    void getCurrentUser_ShouldReturnUserDto() throws Exception {
        // Given
        UserDto expectedUserDto = UserDto.builder()
                .id(1L)
                .email("test@example.com")
                .name("Test User")
                .imageUrl("https://example.com/image.jpg")
                .provider(User.AuthProvider.GOOGLE)
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        when(authService.getCurrentUser()).thenReturn(expectedUserDto);

        // When & Then
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.name").value("Test User"))
                .andExpect(jsonPath("$.imageUrl").value("https://example.com/image.jpg"))
                .andExpect(jsonPath("$.provider").value("GOOGLE"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    @WithMockUser
    void logout_ShouldReturnNoContent() throws Exception {
        // Given
        TokenDto.Request request = new TokenDto.Request();
        request.setToken("refresh-token-value");

        // When & Then
        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }
}