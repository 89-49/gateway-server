package org.pgsg.gateway.feign;

import lombok.extern.slf4j.Slf4j;
import org.pgsg.gateway.auth.AuthDto;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthClientFallbackFactory implements FallbackFactory<AuthClient> {

	@Override
	public AuthClient create(Throwable cause) {
		log.error("[AuthClientFallback] 인증 서비스 호출 실패: {}", cause.getMessage());
		return request -> {
			log.warn("[AuthClientFallback] 인증 서비스 장애로 인해 토큰 검증 실패 처리 (Fallback)");
			return new AuthDto.TokenVerifyResponse(false, "Service Unavailable", new AuthDto.TokenVerifyData(false), null);
		};
	}
}
