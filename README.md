# PGSG Gateway Server

PGSG 마이크로서비스 아키텍처의 강력한 보안 입구이자 통합 관측성(Observability) 허브 역할을 수행하는 게이트웨이 서버입니다.

## 🌟 핵심 기능 (Core Capabilities)

### 1. 보안 입구 정책 (Entry Gate Security)
- **Servlet-based Filter 강제**: `OncePerRequestFilter` 기반의 아키텍처를 채택하여 라우팅 설정과 무관하게 모든 요청에 대한 보안 검사를 강제합니다.
- **헤더 스푸핑(Spoofing) 원천 차단**: 진입 시점에 외부 유입 헤더(`x-user-*`)를 즉시 제거하고 검증된 데이터만 다시 주입하는 선제 방어 시스템을 갖추고 있습니다.
- **실시간 이중 검증**: 게이트웨이의 **로컬 JWT 서명 검증**과 유저 서비스의 **원격 블랙리스트 확인**을 결합한 하이브리드 인증 체계를 구축했습니다.
- **인증 성능 최적화**: 원격 검증 부하를 최소화하기 위해 실시간성을 보장하는 고성능 로컬 캐시(TTL 10-30s)가 적용되어 있습니다.

### 2. 정밀한 분산 추적 (Distributed Tracing)
- **Trace ID 동기화 아키텍처**: Zipkin(`Tracer`)이 생성한 표준 ID를 로그(`MDC`) 및 요청 헤더(`X-Trace-Id`)와 100% 동기화합니다.
- **전 구간 가시성**: 게이트웨이부터 하위 마이크로서비스까지 하나의 고유 ID(Single Source of Truth)로 모든 실행 로그를 연결하여 장애 추적 시간을 획기적으로 단축했습니다.

### 3. 표준화된 장애 및 에러 대응
- **통합 에러 핸들링**: `CustomAuthenticationEntryPoint`를 통해 어떤 인증 실패 상황에서도 공통 모듈의 `ErrorResponse` 규격에 맞는 정교한 JSON 응답을 반환합니다.
- **장애 내성 (Resilience)**: `AuthClientFallbackFactory`를 구현하여 유저 서비스 장애 시에도 게이트웨이가 패닉 없이 안전하게 대응(Fail-Safe)합니다.

### 4. 시스템 최적화 (System Optimization)
- **의존성 격리**: DB를 사용하지 않는 게이트웨이 특성에 맞춰 `@ImportAutoConfiguration`을 통해 불필요한 JPA/DB 설정을 완벽히 제거하고 실행 컨텍스트를 경량화했습니다.

## 🛠 기술 스택
- **Runtime**: Java 21 / Spring Boot 3.5.13
- **Gateway**: Spring Cloud Gateway MVC (Servlet)
- **Security**: Spring Security 6.x
- **Tracing**: Micrometer Tracing (Zipkin Ready)
- **Client**: Spring Cloud OpenFeign

## 📂 주요 문서
- [상세 개선 보고서](./docs/gateway-server-improvement-summary.md): 기술적 해결 방안 및 리팩토링 상세 내역
- [설정 및 작업 이력](./docs/gateway-server-setup-summary.md): Phase별 구축 과정 및 최종 검증 결과

