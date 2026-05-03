package org.pgsg.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pgsg.config.security.jwt.JwtUtils;
import org.pgsg.config.security.token.TokenProvider;
import org.pgsg.config.security.token.TokenType;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class JwtGatewayFilter extends OncePerRequestFilter {

    private final TokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        HttpRequestHeaderWrapper mutableRequest = new HttpRequestHeaderWrapper(request);

        // 1. 스푸핑 방지 — x-user-* 헤더 제거
        mutableRequest.removeHeaders("x-user-");

        log.info("[JwtGatewayFilter] 요청 수신: {} {}", request.getMethod(), request.getRequestURI());

        String accessToken = JwtUtils.resolveToken(request.getHeader(HttpHeaders.AUTHORIZATION));

        // 2. 토큰 검증 실패 시 mutableRequest(x-user-* 제거된 상태)로 다음 단계 진행
        if (accessToken == null || !jwtTokenProvider.validateToken(accessToken)) {
            log.info("[JwtGatewayFilter] 토큰 검증 실패 - 다음 단계 진행");
            filterChain.doFilter(mutableRequest, response);
            return;
        }

        try {
            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            String tokenType = claims.get(JwtUtils.CLAIM_TOKEN_TYPE, String.class);

            if (TokenType.ACCESS.matches(tokenType)) {
                injectUserHeaders(mutableRequest, claims);
                log.info("[JwtGatewayFilter] 토큰 검증 성공 - 사용자 헤더 주입");
            }
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("[JwtGatewayFilter] 토큰 처리 오류: {}", e.getMessage());
        }

        filterChain.doFilter(mutableRequest, response);
    }

    private void injectUserHeaders(HttpRequestHeaderWrapper request, Claims claims) {
        request.putHeader(JwtUtils.HEADER_USER_ID, claims.getSubject());
        request.putHeader(JwtUtils.HEADER_USERNAME, claims.get(JwtUtils.CLAIM_USERNAME, String.class));
        request.putHeader(JwtUtils.HEADER_ROLES, claims.get(JwtUtils.CLAIM_USER_ROLE, String.class));
        request.putHeader(JwtUtils.HEADER_USER_NAME, encodeValue(claims.get(JwtUtils.CLAIM_NAME, String.class)));
        request.putHeader(JwtUtils.HEADER_USER_NICKNAME, encodeValue(claims.get(JwtUtils.CLAIM_NICKNAME, String.class)));

        Boolean enabled = claims.get(JwtUtils.CLAIM_ENABLED, Boolean.class);
        request.putHeader(JwtUtils.HEADER_ENABLED, enabled != null ? enabled.toString() : "false");
    }

    private String encodeValue(String value) {
        return Optional.ofNullable(value)
                .map(val -> URLEncoder.encode(val, StandardCharsets.UTF_8))
                .orElse("");
    }
}