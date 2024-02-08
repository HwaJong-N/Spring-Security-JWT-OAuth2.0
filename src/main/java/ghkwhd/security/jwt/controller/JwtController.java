package ghkwhd.security.jwt.controller;

import ghkwhd.security.jwt.exception.CustomJwtException;
import ghkwhd.security.jwt.utils.JwtConstants;
import ghkwhd.security.jwt.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class JwtController {

    @RequestMapping("/refresh")
    public Map<String, Object> refresh(@RequestHeader("Authorization") String authHeader, String refreshToken) {
        log.info("Refresh Token = {}", refreshToken);
        if (authHeader == null) {
            throw new CustomJwtException("Access Token 이 존재하지 않습니다");
        } else if (!authHeader.startsWith(JwtConstants.JWT_TYPE)) {
            throw new CustomJwtException("BEARER 로 시작하지 않는 올바르지 않은 토큰 형식입니다");
        }

        String accessToken = JwtUtils.getTokenFromHeader(authHeader);

        // Access Token 의 만료 여부 확인
        if (!JwtUtils.isExpired(accessToken)) {
            return Map.of("Access Token", accessToken, "Refresh Token", refreshToken);
        }

        // refreshToken 검증 후 새로운 토큰 생성 후 전달
        Map<String, Object> claims = JwtUtils.validateToken(refreshToken);
        String newAccessToken = JwtUtils.generateToken(claims, JwtConstants.ACCESS_EXP_TIME);

        String newRefreshToken = refreshToken;
        long expTime = JwtUtils.tokenRemainTime((Integer) claims.get("exp"));   // Refresh Token 남은 만료 시간
        log.info("Refresh Token Remain Expire Time = {}", expTime);
        // Refresh Token 의 만료 시간이 한 시간도 남지 않은 경우
        if (expTime <= 60) {
            newRefreshToken = JwtUtils.generateToken(claims, JwtConstants.REFRESH_EXP_TIME);
        }

        return Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken);
    }
}
