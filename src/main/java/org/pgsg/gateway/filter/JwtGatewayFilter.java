package org.pgsg.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pgsg.config.security.jwt.JwtUtils;
import org.pgsg.config.security.token.TokenProvider;
import org.pgsg.config.security.token.TokenType;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component("jwtGatewayFilter")
@RequiredArgsConstructor
public class JwtGatewayFilter implements HandlerFilterFunction<ServerResponse, ServerResponse> {

    private final TokenProvider jwtTokenProvider;

    @Override
    public ServerResponse filter(ServerRequest request, HandlerFunction<ServerResponse> next) throws Exception {
        // 1. 스푸핑 방지 및 빌더 생성
        ServerRequest.Builder builder = ServerRequest.from(request)
                .headers(headers -> headers.keySet().removeIf(name -> name.toLowerCase().startsWith("x-user-")));

        String accessToken = JwtUtils.resolveToken(request.headers().firstHeader(HttpHeaders.AUTHORIZATION));

        // 2. 토큰 검증 실패 시 즉시 다음 단계로 (헤더는 초기화된 상태)
        if (accessToken == null || !jwtTokenProvider.validateToken(accessToken)) {
            return next.handle(builder.build());
        }

        try {
            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            String tokenType = claims.get(JwtUtils.CLAIM_TOKEN_TYPE, String.class);

            if (TokenType.ACCESS.matches(tokenType)) {
                injectUserHeaders(builder, claims);
                log.info("[JwtGatewayFilter] 토큰 검증 성공 - 사용자({}) 헤더 주입", claims.getSubject());
            }
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("[JwtGatewayFilter] 토큰 처리 오류: {}", e.getMessage());
        }

        return next.handle(builder.build());
    }

    private void injectUserHeaders(ServerRequest.Builder builder, Claims claims) {
        builder.header(JwtUtils.HEADER_USER_ID, claims.getSubject());
        builder.header(JwtUtils.HEADER_USERNAME, claims.get(JwtUtils.CLAIM_USERNAME, String.class));
        builder.header(JwtUtils.HEADER_ROLES, claims.get(JwtUtils.CLAIM_USER_ROLE, String.class));
        builder.header(JwtUtils.HEADER_USER_NAME, encodeValue(claims.get(JwtUtils.CLAIM_NAME, String.class)));
        builder.header(JwtUtils.HEADER_USER_NICKNAME, encodeValue(claims.get(JwtUtils.CLAIM_NICKNAME, String.class)));

        Boolean enabled = claims.get(JwtUtils.CLAIM_ENABLED, Boolean.class);
        builder.header(JwtUtils.HEADER_ENABLED, enabled != null ? enabled.toString() : "false");
    }

    private String encodeValue(String value) {
        if (value == null) return "";
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
