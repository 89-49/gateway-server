package org.pgsg.gateway.feign;

import lombok.extern.slf4j.Slf4j;
import org.pgsg.common.response.CommonResponse;
import org.pgsg.gateway.auth.AuthDto;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthClientFallbackFactory implements FallbackFactory<AuthClient> {

	@Override
	public AuthClient create(Throwable cause) {
		log.error("[AuthClientFallback] 인증 서비스 호출 실패: {}", cause.getMessage());
		return request -> new CommonResponse<>(
				false,
				"인증 서비스 장애 (Fallback)",
				new AuthDto.TokenVerifyData(false),
				null
		);
	}
}
