# Gateway Server 개선 및 보안 강화 상세 보고서

본 문서는 Gateway Server의 보안성, 안정성, 및 관측성 향상을 위해 진행된 주요 개선 사항 및 기술적 해결 방안을 상세히 기록합니다.

---

## 1. 필터 아키텍처 개편: Servlet-based Filter 도입

### 배경 및 문제점
Spring Cloud Gateway MVC 환경에서 표준 `HandlerFilterFunction`을 사용할 경우, 필터의 적용 여부가 라우팅 설정(YAML)에 의존하게 됩니다. 원격 Config 서버를 사용하거나 복잡한 라우팅 환경에서는 설정 실수로 인해 특정 경로에서 인증 필터가 누락될 수 있는 보안 허점이 존재했습니다.

### 개선 사항
- **`OncePerRequestFilter` 채택**: 서블릿 컨테이너(Tomcat) 레벨에서 동작하는 필터 방식을 도입하여, 게이트웨이 엔진의 라우팅 설정과 무관하게 모든 HTTP 요청에 대해 필터 실행을 강제했습니다.
- **최상위 우선순위 (`Ordered.HIGHEST_PRECEDENCE + 1`)**: 로깅 필터(`MdcLoggingFilter`) 직후에 실행되도록 보장하여, 보안 검사 이전에 추적 컨텍스트를 완벽히 준비했습니다.
- **코드 리팩토링**: 조기 리턴(Early Return) 패턴을 적용하여 중첩된 `if` 문을 제거하고 가독성을 향상시켰습니다.

---

## 2. 보안 강화 (Security & Authentication)

### 헤더 스푸핑(Header Spoofing) 완벽 차단
- 외부 사용자가 `x-user-id`, `x-user-roles` 등 내부 전용 헤더를 직접 주입하여 권한을 탈취하려는 시도를 원천 차단합니다.
- 모든 요청 진입 시점에 `x-user-` 접두사로 시작하는 모든 헤더를 즉시 제거한 후, 게이트웨이에서 검증된 정보만 다시 주입합니다.

### 이중 검증 시스템 (Local & Remote Hybrid Validation)
1. **로컬 검증 (Local Validation)**: `TokenProvider`를 통해 JWT의 서명 위조 및 만료 여부를 게이트웨이에서 1차적으로 확인합니다.
2. **원격 검증 (Remote Verification)**: 유저 서비스의 내부 API(`authProvider.verifyToken`)를 호출하여 해당 토큰이 블랙리스트에 등록되었는지 실시간으로 확인합니다.
3. **효율적 캐싱**: `AuthProviderImpl` 내부에 `ConcurrentHashMap` 기반의 캐시(TTL 3분)를 구현하여 인증 서비스의 부하를 최소화했습니다.

---

## 3. 분산 추적 및 관측성 (Distributed Tracing)

### Trace ID 동기화 전략 (Zipkin Readiness)
분산 환경에서 로그의 정합성을 100% 보장하기 위해 **"단일 소스 원칙(Single Source of Truth)"**을 적용했습니다.
1. **Tracer 우선순위**: Zipkin(`Tracer`)이 생성한 실제 Trace ID를 최우선으로 가져옵니다.
2. **MDC 동기화**: 결정된 진짜 Trace ID를 `MDC.put("traceId", traceId)`를 통해 로그 시스템에 강제 동기화합니다. 이는 `MdcLoggingFilter`가 생성한 임시 ID를 진짜 ID로 교체하는 역할을 합니다.
3. **전구간 전파**: 동기화된 ID를 하위 서비스로 전달되는 `X-Trace-Id` 헤더에 주입하여, 게이트웨이 로그와 모든 마이크로서비스의 로그가 하나의 트랜잭션 ID로 묶이도록 보장합니다.

---

## 4. 에러 핸들링 표준화

### 공통 에러 응답 (`ErrorResponse`) 적용
- 블랙리스트 감지 등 인증 실패 시, 공통 모듈의 `ErrorResponse` 규격에 맞춘 JSON 응답을 반환합니다.
- `AUTH001`과 같은 표준 에러 코드와 함께 Trace ID를 응답 본문에 포함하여 클라이언트가 장애 문의 시 즉시 로그를 추적할 수 있게 했습니다.

---

## 5. 의존성 격리 및 최적화 (JPA Dependency Isolation)

### 기술적 해결 방안
- **명시적 자동 설정 제외**: `GatewayApplication`에서 `@ImportAutoConfiguration(exclude = AppCtx.class)`를 사용하여 공통 모듈의 JPA 관련 설정을 제외했습니다.
- **맞춤형 컨텍스트 구성 (`GatewayAppCtx`)**: 게이트웨이에 꼭 필요한 공통 기능(Feign, JSON, Error Properties 등)만 선택적으로 `@Import` 하여 최적화된 실행 컨텍스트를 구성했습니다.

---

## 6. 시스템 내결함성 및 통합 테스트

### Feign Client Fallback
- `AuthClientFallbackFactory`를 구현하여 인증 서비스 장애 시에도 게이트웨이가 안전하게 대응(Fail-Safe)하도록 설계했습니다.

### 통합 테스트 성공
- `admin2` 계정 로그인을 통해 발급된 JWT를 사용하여 실시간 토큰 검증 및 사용자 목록 조회(`GET /api/v1/users`) 기능이 완벽하게 동작함을 검증했습니다.

---
