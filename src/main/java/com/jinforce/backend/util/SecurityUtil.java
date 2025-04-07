package com.jinforce.backend.util;

import com.jinforce.backend.exception.UserException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtil {

    private SecurityUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * Get the email of the currently authenticated user
     * @return The email of the authenticated user
     * @throws UserException if no user is authenticated
     */
    public static String getCurrentUserEmail() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new UserException("No authenticated user found");
        }

        return authentication.getName();
    }
}
