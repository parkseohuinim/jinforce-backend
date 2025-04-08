package com.jinforce.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * 스프링 부트 애플리케이션의 시작점
 * @SpringBootApplication은 다음의 어노테이션을 포함합니다:
 * - @Configuration: 스프링 설정 클래스로 지정
 * - @EnableAutoConfiguration: 스프링 부트의 자동 설정 기능 활성화
 * - @ComponentScan: 컴포넌트 스캔(현재 패키지와 하위 패키지의 빈을 찾아 등록)
 * 
 * @EnableJpaAuditing: JPA 엔티티의 생성 및 수정 시간을 자동으로 관리하는 기능 활성화
 */
@SpringBootApplication
@EnableJpaAuditing
public class JinforceBackendApplication {

    /**
     * 애플리케이션 실행을 위한 메인 메서드
     * SpringApplication.run() 메서드로 스프링 부트 애플리케이션을 구동합니다.
     * 
     * @param args 명령줄 인자
     */
    public static void main(String[] args) {
        SpringApplication.run(JinforceBackendApplication.class, args);
    }

}
