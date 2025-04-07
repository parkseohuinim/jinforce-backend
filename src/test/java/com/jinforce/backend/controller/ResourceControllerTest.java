package com.jinforce.backend.controller;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
class ResourceControllerTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Mock
    private AuthService authService;

    @InjectMocks
    private ResourceController resourceController;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void getPublicResource_ShouldBeAccessible() throws Exception {
        mockMvc.perform(get("/resources/public"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("This is a public resource"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void getUserResource_WithUserRole_ShouldBeAccessible() throws Exception {
        // Given
        UserDto userDto = UserDto.builder()
                .id(1L)
                .email("test@example.com")
                .name("Test User")
                .provider(User.AuthProvider.GOOGLE)
                .roles(List.of(User.Role.ROLE_USER))
                .build();

        when(authService.getCurrentUser()).thenReturn(userDto);

        // When & Then
        mockMvc.perform(get("/resources/user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("This is a protected user resource"))
                .andExpect(jsonPath("$.user.id").value(1))
                .andExpect(jsonPath("$.user.email").value("test@example.com"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void getAdminResource_WithUserRole_ShouldBeForbidden() throws Exception {
        mockMvc.perform(get("/resources/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void getAdminResource_WithAdminRole_ShouldBeAccessible() throws Exception {
        mockMvc.perform(get("/resources/admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("This is a protected admin resource"));
    }

    @Test
    void getProtectedResource_WithoutAuthentication_ShouldBeUnauthorized() throws Exception {
        mockMvc.perform(get("/resources/user"))
                .andExpect(status().isUnauthorized());
    }
}
