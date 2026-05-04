package org.pgsg.gateway.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.*;
import java.util.stream.Collectors;

public class HttpRequestHeaderWrapper extends HttpServletRequestWrapper {

	private static final String FORBIDDEN_HEADER_PREFIX = "x-user-";

	private final Map<String, String> customHeaders = new HashMap<>();

	public HttpRequestHeaderWrapper(HttpServletRequest request) {
		super(request);
	}

	public void putHeader(String name, String value) {
		customHeaders.put(name.toLowerCase(), value);
	}

	// x-user- 로 시작하는 헤더 일괄 제거 (스푸핑 방지)
	public void removeHeaders(String prefix) {
		Collections.list(super.getHeaderNames()).stream()
				.filter(name -> name.toLowerCase().startsWith(prefix.toLowerCase()))
				.forEach(name -> customHeaders.remove(name.toLowerCase()));
	}

	@Override
	public String getHeader(String name) {
		String lowerName = name.toLowerCase();
		if (customHeaders.containsKey(lowerName)) {
			return customHeaders.get(lowerName);
		}
		if (lowerName.startsWith(FORBIDDEN_HEADER_PREFIX)) {
			return null;
		}
		return super.getHeader(name);
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		String lowerName = name.toLowerCase();
		String value = customHeaders.get(lowerName);

		if (customHeaders.containsKey(lowerName)) {
			// 리스트의 길이가 1인 경우에도 호환
			return Collections.enumeration(Collections.singletonList(value));
		}
		if (lowerName.startsWith(FORBIDDEN_HEADER_PREFIX)) {
			return Collections.emptyEnumeration();
		}
		return super.getHeaders(name);
	}

	@Override
	public Enumeration<String> getHeaderNames() {
		Set<String> names = Collections.list(super.getHeaderNames()).stream()
				.map(String::toLowerCase)
				.filter(headerName ->
						!customHeaders.containsKey(headerName) && 			// 직접 추가한 요청 헤더가 아니면서
						!headerName.startsWith(FORBIDDEN_HEADER_PREFIX)		//금지된 접두사로 시작하는 헤더가 아님
				)
				.collect(Collectors.toCollection(LinkedHashSet::new));
		names.addAll(customHeaders.keySet());
		return Collections.enumeration(names);
	}
}