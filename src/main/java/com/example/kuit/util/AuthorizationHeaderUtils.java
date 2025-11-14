package com.example.kuit.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

public final class AuthorizationHeaderUtils {

    private AuthorizationHeaderUtils() {
    }

    public static String extractBearerToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(header)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization 헤더 전송 형식이 잘못되었습니다.");
        }

        String[] parts = header.trim().split("\\s+");
        if (parts.length != 2 || !"Bearer".equalsIgnoreCase(parts[0])) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization 헤더 전송 형식이 잘못되었습니다.");
        }

        return parts[1];
    }
}