# Gateway Server 구축 및 보안 아키텍처 작업 이력

## 1. 프로젝트 개요
본 프로젝트는 MSA 환경에서 요청의 진입점 역할을 수행하는 **WebMVC 기반의 Spring Cloud Gateway**입니다. 전역적인 인증 처리와 라우팅 관리를 담당합니다.

## 2. 작업 이력 및 기술적 진화

### 2.1 [Phase 1] 초기 인프라 설정 및 Config Server 통합
- **DataSource 자동 설정 제외**: DB 미사용에 따른 기동 오류를 `DataSourceAutoConfiguration` 제외 설정을 통해 해결.
- **Docker 컨테이너화**: Multi-stage 빌드 및 `.env`를 통한 환경 변수 주입 환경 구축.
- **Config Server 우선순위 해결**: 원격 설정이 로컬 라우팅을 덮어쓰는 문제를 `spring.config.import` 순서 조정 및 `local-routes.yaml` 분리를 통해 해결.

### 2.2 [Phase 2] 서블릿 필터 기반 JWT 인증 구현 (초기 버전)
- **JwtAuthenticationFilter (OncePerRequestFilter)**: 표준 서블릿 필터 방식으로 JWT 검증 로직 구현.
- **HttpRequestHeaderWrapper**: `HttpServletRequest`가 읽기 전용인 서블릿 특성을 극복하기 위해 래퍼 클래스를 구현하여 헤더 주입 및 스푸핑 방지 기능 수행.
- **성과**: 게이트웨이 단에서의 1차적인 인증 및 정보 전달(Header Propagation) 메커니즘을 최초로 확립.

### 2.3 [Phase 3] 네이티브 게이트웨이 필터로 리팩토링 (현재 버전)
- **JwtGatewayFilter (HandlerFilterFunction)**: 서블릿 필터를 제거하고 Spring Cloud Gateway WebMVC의 표준인 `HandlerFilterFunction`으로 전환.
- **ServerRequest Mutability 활용**: 게이트웨이 빌트인 기능을 사용하여 별도의 래퍼 클래스 없이도 안전하게 헤더를 초기화하고 주입하는 구조로 단순화.
- **가독성 개선**: Guard Clauses 패턴을 적용하여 중첩 `if`문을 제거하고 로직을 평탄화.
- **성과**: 서블릿 종속성을 줄이고 게이트웨이 프레임워크와의 결합도를 높여 성능과 유지보수성 향상.

## 3. 핵심 클래스 현황
- `GatewayApplication.java`: 애플리케이션 엔트리 포인트.
- `JwtGatewayFilter.java`: 현재 활성화된 네이티브 인증 필터.
- `JwtConfig.java`: 공통 모듈 유틸리티 빈 등록.
- `GatewaySecurityConfig.java`: 전역 보안 정책 구성.

## 4. 검증 결과
- `/api/v1/auth/login` 라우팅 및 토큰 발급 테스트 완료.
- 발급된 토큰을 통한 게이트웨이 필터의 헤더 변환 및 사용자 정보 주입 정상 동작 확인.
- Gradle/Docker 캐시 초기화를 통한 깨끗한 빌드 환경 검증 완료.

## 5. 향후 아키텍처 결정 사항 (블랙리스트 검증)
- **데이터 소유권**: Redis는 오직 `user-service`만 소유한다는 원칙 고수.
- **검증 방식**: 게이트웨이가 `user-service`의 내부 API(FeignClient 등)를 호출하여 블랙리스트 여부 확인.
- **최적화**: 네트워크 부하 감소를 위해 게이트웨이 내부에 **로컬 메모리 캐시** 도입 검토.
