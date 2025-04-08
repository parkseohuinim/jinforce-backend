package com.jinforce.backend.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Swagger(OpenAPI) 설정 클래스
 * API 문서화 및 테스트 UI 제공
 */
@Configuration
public class SwaggerConfig {

    /**
     * OpenAPI 구성
     * JWT 인증 포함 API 문서 설정
     */
    @Bean
    public OpenAPI openAPI() {
        // JWT 보안 스키마 설정
        String jwtSchemeName = "JWT";
        SecurityRequirement securityRequirement = new SecurityRequirement().addList(jwtSchemeName);
        Components components = new Components()
                .addSecuritySchemes(jwtSchemeName, 
                        new SecurityScheme()
                                .name(jwtSchemeName)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT"));

        // API 기본 정보 설정
        return new OpenAPI()
                .info(new Info()
                        .title("Jinforce API")
                        .description("Jinforce 백엔드 API 문서")
                        .version("v1.0.0")
                        .contact(new Contact()
                                .name("Jinforce Team")
                                .email("parkseohuinim@gmail.com")))
                .addSecurityItem(securityRequirement)
                .components(components);
    }
} 