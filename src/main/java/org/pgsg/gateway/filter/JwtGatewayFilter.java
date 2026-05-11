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
import org.springframework.util.AntPathMatcher;
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
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();
    private static final List<String> WHITELIST = List.of(
            "/api/v1/auth/login",
            "/api/v1/auth/signup",
            "/api/v1/auth/reissue",
            "/actuator/health",
            "/actuator/health/**",
            "/actuator/info"
    );

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

        // 1. 추적 ID 동기화 및 보안 헤더 초기화
        String traceId = initializeHeaders(mutableRequest, tracer);
        
        log.info("[JwtGatewayFilter] 요청 수신: {} {}", request.getMethod(), request.getRequestURI());
        String accessToken = JwtUtils.resolveToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        String path = request.getRequestURI();

        // 2. 화이트리스트 경로인 경우: 즉시 통과 (패턴 매칭 지원)
        if (isWhitelisted(path)) {
            filterChain.doFilter(mutableRequest, response);
            return;
        }

        // 3. 토큰이 없는 경우: 즉시 차단 (화이트리스트 제외)
        if (accessToken == null) {
            log.warn("[JwtGatewayFilter] Access 토큰 누락 - 차단 (TraceID: {})", traceId);
            customAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("Access 토큰이 필요합니다."));
            return;
        }

        // 4. 통합 인증 프로세스 수행 (로컬 검증 -> 원격 검증 -> 헤더 주입)
        if (!authenticate(mutableRequest, response, accessToken, traceId)) {
            return; // 검증 실패 시 응답 종료
        }

        filterChain.doFilter(mutableRequest, response);
    }

    private boolean isWhitelisted(String path) {
        return WHITELIST.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    /**
     * 통합 인증 로직 (최적화된 순서)
     * 1. 로컬 검증 (Signature, Expiration) - 비용 낮음
     * 2. 원격 검증 (Blacklist 체크) - 비용 높음
     * 3. Claims 파싱 및 헤더 주입
     */
    private boolean authenticate(HttpRequestHeaderWrapper request, HttpServletResponse response, String accessToken, String traceId) throws IOException, ServletException {
        try {
            // [Step 1] 로컬 검증 (가장 먼저 수행하여 잘못된 토큰의 원격 호출 방지)
            if (!jwtTokenProvider.validateToken(accessToken)) {
                log.info("[JwtGatewayFilter] 유효하지 않은 토큰 - 차단 (TraceID: {})", traceId);
                customAuthenticationEntryPoint.commence(request, response,
                        new InsufficientAuthenticationException("유효하지 않거나 만료된 토큰입니다."));
                return false;
            }

            // [Step 2] 원격 검증 (로컬 검증 통과 시에만 실시간 블랙리스트 확인)
            if (!authProvider.verifyToken(accessToken)) {
                log.warn("[JwtGatewayFilter] 블랙리스트 토큰 감지 - 차단 (TraceID: {})", traceId);
                customAuthenticationEntryPoint.commence(request, response,
                        new InsufficientAuthenticationException("이미 로그아웃되었거나 사용할 수 없는 토큰입니다."));
                return false;
            }

            // [Step 3] Claims 추출 및 토큰 타입 확인
            Claims claims = jwtTokenProvider.parseClaims(accessToken);
            String tokenType = claims.get(JwtUtils.CLAIM_TOKEN_TYPE, String.class);

            if (!TokenType.ACCESS.matches(tokenType)) {
                log.warn("[JwtGatewayFilter] 허용되지 않은 토큰 타입 ({}) - 차단 (TraceID: {})", tokenType, traceId);
                customAuthenticationEntryPoint.commence(request, response,
                        new InsufficientAuthenticationException("Access 토큰이 필요합니다."));
                return false;
            }

            // [Step 4] 검증 완료 - 사용자 헤더 주입
            injectUserHeaders(request, claims);
            log.info("[JwtGatewayFilter] 인증 성공 - 사용자 헤더 주입 (TraceID: {})", traceId);
            return true;

        } catch (JwtException | IllegalArgumentException e) {
            log.error("[JwtGatewayFilter] 인증 처리 중 예외 발생: {} (TraceID: {})", e.getMessage(), traceId);
            customAuthenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("토큰 인증 중 오류가 발생했습니다."));
            return false;
        }
    }

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
                .orElse(null);
    }
}
