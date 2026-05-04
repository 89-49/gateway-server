package org.pgsg.gateway.feign;

import org.pgsg.common.response.CommonResponse;
import org.pgsg.gateway.auth.AuthDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", fallbackFactory = AuthClientFallbackFactory.class)
public interface AuthClient {

	@PostMapping(value = "/internal/v1/auth/verify")
	CommonResponse<AuthDto.TokenVerifyResponse> verifyToken(@RequestBody AuthDto.TokenVerifyRequest request);
}
