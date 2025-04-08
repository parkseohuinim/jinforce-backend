plugins {
    java
    id("org.springframework.boot") version "3.5.0-SNAPSHOT"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.jinforce"
version = "0.0.1-SNAPSHOT"

// Java 21 사용 설정
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

// 의존성을 가져올 저장소 설정
repositories {
    mavenCentral()
    maven { url = uri("https://repo.spring.io/milestone") }
    maven { url = uri("https://repo.spring.io/snapshot") }
}

dependencies {
    // 스프링 부트 핵심 의존성
    implementation("org.springframework.boot:spring-boot-starter-web") // 웹 구현
    implementation("org.springframework.boot:spring-boot-starter-security") // 보안
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client") // OAuth2
    implementation("org.springframework.boot:spring-boot-starter-data-jpa") // JPA
    implementation("org.springframework.boot:spring-boot-starter-validation") // 검증

    // JWT 라이브러리 - 인증에 사용
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")

    // 데이터베이스 드라이버
    implementation("org.postgresql:postgresql")

    // 환경변수 설정 라이브러리
    implementation("me.paulschwarz:spring-dotenv:3.0.0")

    // Lombok - 코드 간소화
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    // 테스트 관련 의존성
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// 테스트 설정
tasks.withType<Test> {
    useJUnitPlatform()
    
    // 테스트 로그 설정 - 더 자세한 테스트 결과 표시
    testLogging {
        events("passed", "skipped", "failed")
        showExceptions = true
        showCauses = true
        showStackTraces = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true // 표준 출력 표시 (System.out, System.err)
    }
}
