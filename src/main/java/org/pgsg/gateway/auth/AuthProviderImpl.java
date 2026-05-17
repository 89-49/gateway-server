package org.pgsg.gateway.auth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.pgsg.gateway.client.AuthClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class AuthProviderImpl implements AuthProvider {

	private final Cache<String, Boolean> tokenCache;
	private final AuthClient authClient;

	public AuthProviderImpl(AuthClient authClient) {
		this.authClient = authClient;
		this.tokenCache = Caffeine.newBuilder()
				.expireAfterWrite(30, TimeUnit.SECONDS)
				.maximumSize(10000)
				.build();
	}

	@Override
	public Mono<Boolean> verifyToken(String accessToken) {
		Boolean cachedResult = tokenCache.getIfPresent(accessToken);

		if (cachedResult != null) {
			return Mono.just(cachedResult);
		}

		return authClient.verifyToken(new AuthDto.TokenVerifyRequest(accessToken))
				.map(response -> response != null
						&& response.success()
						&& response.data() != null
						&& response.data().isVerifiedToken())
				.doOnNext(result -> tokenCache.put(accessToken, result))
				.onErrorReturn(false);
	}
}

