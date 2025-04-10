package com.jinforce.backend.service.impl;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;
import com.jinforce.backend.exception.UserException;
import com.jinforce.backend.repository.UserRepository;
import com.jinforce.backend.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 사용자 관리 서비스 구현체
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    /**
     * 모든 사용자 목록을 조회합니다.
     *
     * @return 모든 사용자 정보 목록
     */
    @Override
    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserDto::fromEntity)
                .collect(Collectors.toList());
    }

    /**
     * 이메일로 사용자를 조회합니다.
     *
     * @param email 사용자 이메일
     * @return 사용자 정보
     */
    @Override
    @Transactional(readOnly = true)
    public UserDto getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(UserDto::fromEntity)
                .orElseThrow(() -> new UserException("사용자를 찾을 수 없습니다: " + email));
    }

    /**
     * 특정 사용자에게 관리자 권한을 부여합니다.
     *
     * @param email 권한을 부여할 사용자의 이메일
     * @return 업데이트된 사용자 정보
     */
    @Override
    @Transactional
    public UserDto addAdminRole(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserException("사용자를 찾을 수 없습니다: " + email));
        
        // 이미 관리자인 경우 처리
        if (user.isAdmin()) {
            log.info("사용자 {}는 이미 관리자 권한을 가지고 있습니다.", email);
            return UserDto.fromEntity(user);
        }
        
        // 관리자 권한 추가
        log.info("사용자 {}에게 관리자 권한을 추가합니다.", email);
        user.addAdminRole();
        userRepository.save(user);
        
        return UserDto.fromEntity(user);
    }

    /**
     * 사용자 시스템 통계 정보를 조회합니다.
     *
     * @return 시스템 통계 정보
     */
    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> getSystemStats() {
        long userCount = userRepository.count();
        long adminCount = userRepository.findAll().stream()
                .filter(User::isAdmin)
                .count();
        
        return Map.of(
                "totalUsers", userCount,
                "adminUsers", adminCount,
                "systemVersion", "1.0.0",
                "lastUpdated", System.currentTimeMillis()
        );
    }
} 