package com.example.kuit.service;

import com.example.kuit.dto.response.LoginResponse;
import com.example.kuit.dto.response.ReissueResponse;
import com.example.kuit.jwt.JwtUtil;
import com.example.kuit.model.RefreshToken;
import com.example.kuit.model.Role;
import com.example.kuit.model.User;
import com.example.kuit.repository.RefreshTokenRepository;
import com.example.kuit.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    public LoginResponse login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유저가 존재하지 않습니다."));

        if (!user.password().equals(password)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "비밀번호가 일치하지 않습니다.");
        }

        String accessToken = jwtUtil.generateAccessToken(username, user.role().name());
        String refreshToken = jwtUtil.generateRefreshToken(username, user.role().name());

        refreshTokenRepository.deleteByUsername(username);
        refreshTokenRepository.save(new RefreshToken(username, refreshToken, jwtUtil.getExpiration(refreshToken)));

        return LoginResponse.of(accessToken, refreshToken);
    }

    public ReissueResponse reissue(String username, Role role, String refreshToken) {
        // TODO: DB에 RefreshToken 존재 여부 확인 - refreshTokenRepository.findByUsername 메서드 활용
        RefreshToken storedToken = refreshTokenRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("리프레시 토큰이 존재하지 않습니다."));

        if (!storedToken.token().equals(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "RefreshToken 이 일치하지 않습니다.");
        }

        // TODO: DB에 저장되어있는 토큰의 만료 여부 검사 - refresh
        if (storedToken.isExpired()) {
            refreshTokenRepository.deleteByUsername(username);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "RefreshToken 이 만료되었습니다.");
        }

//        String newAccessToken = jwtUtil.generateAccessToken(username, role.name());
//        String newRefreshToken = jwtUtil.generateRefreshToken(username, role.name());

        // TODO: DB에 저장되어있는 토큰과 요청으로 받은 토큰의 동일 여부 검사
        String accessToken = jwtUtil.generateAccessToken(username, role.name());

        // TODO: AccessToken 재발급
        return ReissueResponse.of(accessToken, refreshToken);
    }
}
