package org.pgsg.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.pgsg.config.security.CustomAuthenticationEntryPoint;
import org.pgsg.config.security.jwt.JwtUtils;
import org.pgsg.config.security.token.TokenProvider;
import org.pgsg.config.security.token.TokenType;
import org.pgsg.gateway.auth.AuthProvider;
import org.slf4j.MDC;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class JwtGatewayFilter extends OncePerRequestFilter {

    private static final String HEADER_TRACE_ID = "X-Trace-Id";
    private static final List<String> WHITELIST = List.of("/api/v1/auth/login", "/api/v1/auth/signup");

    private final Tracer tracer;
    private final TokenProvider jwtTokenProvider;
    private final AuthProvider authProvider;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    public JwtGatewayFilter(
            Tracer tracer,
            TokenProvider jwtTokenProvider,
            AuthProvider authProvider,
            @Lazy CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        this.tracer = tracer;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authProvider = authProvider;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        HttpRequestHeaderWrapper mutableRequest = new HttpRequestHeaderWrapper(request);

        // 1. 스푸핑 방지 및 추적 ID 동기화
        String traceId = initializeHeaders(mutableRequest, tracer);
        
        log.info("[JwtGatewayFilter] 요청 수신: {} {}", request.getMethod(), request.getRequestURI());
        String accessToken = JwtUtils.resolveToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        String path = request.getRequestURI();

        // 2. 토큰이 없거나, 로그인/회원가입 진행 시: 즉시 통과
        if (WHITELIST.contains(path) || accessToken == null) {
            filterChain.doFilter(mutableRequest, response);
            return;
        }

        // 3. 블랙리스트 확인: 차단 시 즉시 종료 (AuthenticationEntryPoint 활용)
        if (!authProvider.verifyToken(accessToken)) {
            log.error("[JwtGatewayFilter] 블랙리스트 토큰 감지 - 차단 (TraceID: {})", traceId);
            customAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("이미 로그아웃되었거나 유효하지 않은 토큰입니다."));
            return;
        }

        // 4. 토큰 유효성 검증 및 헤더 주입 -> 다음 단계 진행
        processAuthentication(mutableRequest, accessToken);
        filterChain.doFilter(mutableRequest, response);
    }

    private void processAuthentication(HttpRequestHeaderWrapper request, String accessToken) {
        try {
            if (!jwtTokenProvider.validateToken(accessToken)) {
                log.info("[JwtGatewayFilter] 유효하지 않은 토큰 - 헤더 주입 없이 진행");
                return;
            }

            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            String tokenType = claims.get(JwtUtils.CLAIM_TOKEN_TYPE, String.class);

            if (TokenType.ACCESS.matches(tokenType)) {
                injectUserHeaders(request, claims);
                log.info("[JwtGatewayFilter] 토큰 검증 성공 - 사용자 헤더 주입");
            }
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("[JwtGatewayFilter] 토큰 처리 중 오류 발생: {}", e.getMessage());
        }
    }

    /**
     * 추적 ID 동기화 및 보안 헤더 초기화
     * 1. Tracer(Zipkin) -> 2. MDC(LoggingFilter) -> 3. UUID 순으로 ID 결정
     */
    private String initializeHeaders(HttpRequestHeaderWrapper mutableRequest, Tracer tracer) {
        // traceId: Zipkin의 traceId 할당 후 MDC에 저장 -> Zipkin과의 연동을 위해 32글자 유지(필요 시 수정 예정)
        String traceId = (tracer.currentSpan() != null)
                ? Objects.requireNonNull(tracer.currentSpan()).context().traceId()
                : MDC.get("traceId");

        if (traceId == null) {
            traceId = UUID.randomUUID().toString().replace("-", "");
        }

        // MDC와 헤더를 결정된 ID로 일치시킴
        MDC.put("traceId", traceId);
        mutableRequest.removeHeaders("x-user-");
        mutableRequest.putHeader(HEADER_TRACE_ID, traceId);
        
        return traceId;
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
