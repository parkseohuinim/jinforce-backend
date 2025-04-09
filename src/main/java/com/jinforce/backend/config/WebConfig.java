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
     * 클라이언트 Accept 헤더를 주지 않았을 때도 서버버가 기본적으로 JSON 으로 응답하게 하려는 목적
     * 확장자 .json 으로 접근할 때도 명확하게 JSON 으로 응답하도록 함
     */
    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
        configurer
            .defaultContentType(MediaType.APPLICATION_JSON)
            .mediaType("json", MediaType.APPLICATION_JSON);
    }
    
    /**
     * 응답 객체를 JSON 으로 변환할 때 사용하는 Jackson 기반 컨버터를 명시적으로 등록
     * 이 컨버터는 내부적으로 UTF-8 인코딩으로 응답을 설정
     * 기본 설정에 의존하지 않고 명확하게 내가 지정한 ObjectMapper 를 사용하도록 강제
     */
    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new MappingJackson2HttpMessageConverter(objectMapper()));
    }

    /**
     * MappingJackson2HttpMessageConverter 에 사용할 ObjectMapper 를 직접 관리
     * 향후 날짜 포맷, snake_case 변환 등 추가 설정이 필요할 경우 이 메서드에서 관리
     */
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
} 