package org.pgsg.gateway.auth;

import lombok.RequiredArgsConstructor;
import org.pgsg.gateway.feign.AuthClient;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
public class AuthProviderImpl implements AuthProvider {

	private final AuthClient authClient;

	// 간단한 로컬 캐시 (토큰별 검증 결과 저장)
	private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
	private static final long CACHE_TTL = 60 * 3000; // 캐시 유지 시간: 3분

	@Override
	public boolean verifyToken(String accessToken) {
		CacheEntry entry = cache.get(accessToken);

		// 캐시가 유효하면 바로 반환
		if (entry != null && !entry.isExpired()) {
			return entry.result;
		}

		// 캐시가 없거나 만료되었으면 Feign 호출
		AuthDto.TokenVerifyResponse response = authClient.verifyToken(new AuthDto.TokenVerifyRequest(accessToken)).data();

		// 결과 추출 (success 가 true 이고 isVerifiedToken 이 true 인 경우에만 성공) 및 캐싱
		boolean result = response != null && response.success() && response.data() != null && response.data().isVerifiedToken();
		cache.put(accessToken, new CacheEntry(result, System.currentTimeMillis() + CACHE_TTL));

		cleanupCache();

		return result;
	}

	// 만료된 캐시를 가끔 정리 (메모리 누수 방지)
	private void cleanupCache() {
		if (cache.size() > 500) { // 캐시 크기가 일정 이상 커지면 정리
			cache.entrySet().removeIf(e -> e.getValue().isExpired());
		}
	}

	private record CacheEntry(boolean result, long expiryTime) {
		boolean isExpired() {
			return System.currentTimeMillis() > expiryTime;
		}
	}
}
