package org.pgsg.gateway.client;

import org.pgsg.common.response.CommonResponse;
import org.pgsg.gateway.auth.AuthDto;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

//@FeignClient(name = "user-service", fallbackFactory = AuthClientFallbackFactory.class)
@Component
public class AuthClient {

	private final WebClient webClient;

	public AuthClient(WebClient.Builder builder) {
		this.webClient = builder.baseUrl("lb://user-service").build();
	}

	public Mono<CommonResponse<AuthDto.TokenVerifyData>> verifyToken(AuthDto.TokenVerifyRequest request) {
		return webClient.post()
				.uri("/internal/v1/auth/verify")
				.bodyValue(request)
				.retrieve()
				.bodyToMono(new ParameterizedTypeReference<CommonResponse<AuthDto.TokenVerifyData>>() {})
				.onErrorReturn(new CommonResponse<>(false, "인증 서비스 장애", new AuthDto.TokenVerifyData(false), null));
	}
}
