package com.jinforce.backend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * 스프링 MVC 웹 설정 클래스
 * 응답 인코딩 및 Content-Type 관련 설정
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * Content-Type 협상 설정
     * 모든 응답을 UTF-8로 인코딩된 JSON으로 설정
     */
    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
        configurer
            .defaultContentType(MediaType.APPLICATION_JSON)
            .mediaType("json", MediaType.APPLICATION_JSON);
    }
    
    /**
     * HTTP 메시지 컨버터 설정
     * JSON 응답에 대한 UTF-8 인코딩 설정
     */
    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new MappingJackson2HttpMessageConverter(objectMapper()));
    }

    /**
     * ObjectMapper 빈 설정
     * JSON 직렬화/역직렬화에 사용되는 설정
     */
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
} 