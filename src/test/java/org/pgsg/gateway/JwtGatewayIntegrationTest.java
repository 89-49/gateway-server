package org.pgsg.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.pgsg.common.response.CommonResponse;
import org.pgsg.config.security.token.TokenProvider;
import org.pgsg.gateway.auth.AuthDto;
import org.pgsg.gateway.feign.AuthClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import org.pgsg.config.security.jwt.JwtUtils;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class JwtGatewayIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TokenProvider tokenProvider;

    @MockitoBean
    private AuthClient authClient;

    /**
     * 테스트용 컨트롤러: 게이트웨이 필터를 거쳐 주입된 헤더를 확인하는 용도
     */
    @TestConfiguration
    @RestController
    static class TestDownstreamController {
        @GetMapping("/test/headers")
        public Map<String, String> getHeaders(
                @RequestHeader(value = "x-user-id", required = false) String userId,
                @RequestHeader(value = "x-user-roles", required = false) String roles
        ) {
            return Map.of(
                    "userId", userId != null ? userId : "null",
                    "roles", roles != null ? roles : "null"
            );
        }

        @GetMapping("/api/v1/auth/login")
        public String whitelist() {
            return "ok";
        }
    }

    @Test
    @DisplayName("유효한 토큰 요청 시 사용자 헤더가 정상 주입되어야 한다")
    void success_token_injection() throws Exception {
        // given
        String token = "valid-token";
        String userId = "12345";
        String role = "ROLE_USER";

        Mockito.when(tokenProvider.validateToken(token)).thenReturn(true);
        
        Claims claims = Jwts.claims()
                .subject(userId)
                .add(JwtUtils.CLAIM_USER_ROLE, role)
                .add(JwtUtils.CLAIM_TOKEN_TYPE, "access") // TokenType.ACCESS.getValue() 값인 "access" 사용
                .add(JwtUtils.CLAIM_USERNAME, "tester")
                .add(JwtUtils.CLAIM_NAME, "TesterName")
                .add(JwtUtils.CLAIM_NICKNAME, "TestNick")
                .add(JwtUtils.CLAIM_ENABLED, true)
                .build();
        Mockito.when(tokenProvider.parseClaims(token)).thenReturn(claims);

        Mockito.when(authClient.verifyToken(any()))
                .thenReturn(new CommonResponse<>(true, "success", new AuthDto.TokenVerifyData(true), null));

        // when & then
        mockMvc.perform(get("/test/headers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value(userId))
                .andExpect(jsonPath("$.data.roles").value(role));
    }

    @Test
    @DisplayName("블랙리스트 토큰 요청 시 401 에러를 반환해야 한다")
    void fail_blacklisted_token() throws Exception {
        // given
        String token = "blacklisted-token";
        Mockito.when(tokenProvider.validateToken(token)).thenReturn(true);
        
        // 원격 검증에서 실패(블랙리스트) 반환
        Mockito.when(authClient.verifyToken(any()))
                .thenReturn(new CommonResponse<>(true, "fail", new AuthDto.TokenVerifyData(false), null));

        // when & then
        mockMvc.perform(get("/test/headers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("화이트리스트 경로는 토큰 없이 통과되어야 한다")
    void success_whitelist() throws Exception {
        mockMvc.perform(get("/api/v1/auth/login"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("외부에서 주입한 보안 헤더(x-user-)는 무시되어야 한다")
    void success_spoofing_protection() throws Exception {
        // given
        String token = "valid-token";
        String realUserId = "12345";

        Mockito.when(tokenProvider.validateToken(token)).thenReturn(true);
        Claims claims = Jwts.claims()
                .subject(realUserId)
                .add(JwtUtils.CLAIM_USER_ROLE, "ROLE_USER")
                .add(JwtUtils.CLAIM_TOKEN_TYPE, "access") // "access" 사용
                .add(JwtUtils.CLAIM_USERNAME, "tester")
                .add(JwtUtils.CLAIM_NAME, "TesterName")
                .add(JwtUtils.CLAIM_NICKNAME, "TestNick")
                .add(JwtUtils.CLAIM_ENABLED, true)
                .build();
        Mockito.when(tokenProvider.parseClaims(token)).thenReturn(claims);
        Mockito.when(authClient.verifyToken(any())).thenReturn(new CommonResponse<>(true, "success", new AuthDto.TokenVerifyData(true), null));

        // when & then
        mockMvc.perform(get("/test/headers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .header("x-user-id", "99999")) // 스푸핑 시도
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value(realUserId)); // 게이트웨이가 주입한 값이어야 함
    }
}
