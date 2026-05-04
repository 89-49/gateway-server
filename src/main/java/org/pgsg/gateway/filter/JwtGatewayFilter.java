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
    private static final List<String> WHITELIST = List.of("/api/v1/auth/login", "/api/v1/auth/signup", "/api/v1/auth/reissue");

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

        // 2. 토큰이 없거나, 로그인/회원가입 진행 시: 즉시 통과 (Public API)
        if (WHITELIST.contains(path) || accessToken == null) {
            filterChain.doFilter(mutableRequest, response);
            return;
        }

        // 3. 블랙리스트 확인: 차단 시 즉시 종료
        if (!authProvider.verifyToken(accessToken)) {
            log.warn("[JwtGatewayFilter] 블랙리스트 토큰 감지 - 차단 (TraceID: {})", traceId);
            customAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("이미 로그아웃되었거나 유효하지 않은 토큰입니다."));
            return;
        }

        // 4. 토큰 유효성 검증 및 헤더 주입 -> 실패 시 즉시 종료 (Fail-Fast)
        if (!processAuthentication(mutableRequest, response, accessToken, traceId)) {
            return;
        }

        filterChain.doFilter(mutableRequest, response);
    }

    /**
     * 토큰의 유효성을 검증하고 사용자 헤더를 주입합니다.
     * 실패 시 AuthenticationEntryPoint를 통해 응답을 종료합니다.
     */
    private boolean processAuthentication(HttpRequestHeaderWrapper request, HttpServletResponse response, String accessToken, String traceId) throws IOException, ServletException {
        try {
            // 로컬 검증 (위조/만료 여부)
            if (!jwtTokenProvider.validateToken(accessToken)) {
                log.info("[JwtGatewayFilter] 유효하지 않은 토큰 - 차단 (TraceID: {})", traceId);
                customAuthenticationEntryPoint.commence(request, response,
                        new InsufficientAuthenticationException("유효하지 않거나 만료된 토큰입니다."));
                return false;
            }

            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            String tokenType = claims.get(JwtUtils.CLAIM_TOKEN_TYPE, String.class);

            // Access 토큰 타입 확인
            if (TokenType.ACCESS.matches(tokenType)) {
                injectUserHeaders(request, claims);
                log.info("[JwtGatewayFilter] 토큰 검증 성공 - 사용자 헤더 주입 (TraceID: {})", traceId);
                return true;
            }

            log.warn("[JwtGatewayFilter] 허용되지 않은 토큰 타입 ({}) - 차단 (TraceID: {})", tokenType, traceId);
            customAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("Access 토큰이 필요합니다."));
            return false;

        } catch (JwtException | IllegalArgumentException e) {
            log.error("[JwtGatewayFilter] 토큰 처리 중 예외 발생: {} (TraceID: {})", e.getMessage(), traceId);
            customAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("토큰 검증 중 오류가 발생했습니다."));
            return false;
        }
    }

    /**
     * 추적 ID 동기화 및 보안 헤더 초기화
     */
    private String initializeHeaders(HttpRequestHeaderWrapper mutableRequest, Tracer tracer) {
        String traceId = (tracer.currentSpan() != null)
                ? Objects.requireNonNull(tracer.currentSpan()).context().traceId()
                : MDC.get("traceId");

        if (traceId == null) {
            traceId = UUID.randomUUID().toString().substring(0, 8);
        }

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
