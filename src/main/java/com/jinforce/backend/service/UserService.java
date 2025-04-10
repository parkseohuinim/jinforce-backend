package com.jinforce.backend.service;

import com.jinforce.backend.dto.UserDto;
import com.jinforce.backend.entity.User;

import java.util.List;

/**
 * 사용자 관리 서비스 인터페이스
 * 사용자 정보 조회 및 권한 관리 기능 제공
 */
public interface UserService {

    /**
     * 모든 사용자 목록을 조회합니다.
     *
     * @return 모든 사용자 정보 목록
     */
    List<UserDto> getAllUsers();

    /**
     * 이메일로 사용자를 조회합니다.
     *
     * @param email 사용자 이메일
     * @return 사용자 정보
     */
    UserDto getUserByEmail(String email);

    /**
     * 특정 사용자에게 관리자 권한을 부여합니다.
     *
     * @param email 권한을 부여할 사용자의 이메일
     * @return 업데이트된 사용자 정보
     */
    UserDto addAdminRole(String email);

    /**
     * 사용자의 시스템 통계 정보를 조회합니다.
     *
     * @return 시스템 통계 정보
     */
    java.util.Map<String, Object> getSystemStats();
} 