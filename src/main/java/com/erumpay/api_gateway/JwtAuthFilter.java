package com.erumpay.api_gateway;


import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import reactor.core.publisher.Mono;

@Component  // Spring Framework를 통해 객체 관리
public class JwtAuthFilter implements GlobalFilter, Ordered {

    // StripPrefix 등 라우트별 GatewayFilter보다 확실히 먼저 실행되도록 보장.
    // (작을수록 우선) — WHITE_LIST_PATHS/PG_PATH_PREFIXES는 prefix가 잘리기 *전* path 기준으로 매칭됨.
    @Override
    public int getOrder() {
        return -1;
    }

    // auth-service(B2C 사용자) 토큰 검증용 secret
    @Value("${jwt.secret}")
    private String userSecret;

    // pg-auth-service(B2B 가맹점/관리자) 토큰 검증용 secret
    @Value("${pg.jwt.secret}")
    private String pgSecret;

    private SecretKey userKey;
    private SecretKey pgKey;

    // 토큰 검증 없이 통과하는 화이트리스트 등록 (prefix 매칭 — startsWith)
    // 매칭 기준: Spring Cloud Gateway의 StripPrefix=1 필터가 적용되기 *전* path.
    private static final List<String> WHITE_LIST_PATHS = List.of(
        // ── 헬스체크 ──
        "/actuator/health",
        "/actuator/info",

        // ── Swagger 통합 (api-gateway 자체 UI) ──
        "/swagger-ui",
        "/v3/api-docs",
        "/webjars",

        // ── Swagger 통합 (각 서비스 OpenAPI 문서) ──
        // 다운스트림 서비스가 /v3/api-docs를 아직 안 열어둔 경우엔 단순히 404가 떨어집니다(보안 영향 없음).
        "/auth-service/v3/api-docs",
        "/card-service/v3/api-docs",
        "/payment-service/v3/api-docs",
        "/recommendation-service/v3/api-docs",
        "/notification-service/v3/api-docs",
        "/pg-auth-service/v3/api-docs",
        "/billing-key-service/v3/api-docs",
        "/pg-payment-service/v3/api-docs",
        "/merchant-service/v3/api-docs",
        "/card-simulator-service/v3/api-docs",

        // ── auth-service (B2C 사용자, 로그인/재발급) ──
        "/auth-service/api/v1/auth/kakao/login",
        "/auth-service/api/v1/auth/token/refresh",

        // ── pg-auth-service (B2B 가맹점/관리자, 로그인/재발급/가입 흐름) ──
        // 가입 흐름(terms/agree, signup)은 SIGNUP 토큰을 사용하므로 GW에서 ACCESS 검증 불가 → WL 후 pg-auth가 자체 검증
        "/pg-auth-service/api/v1/auth/health",
        "/pg-auth-service/api/v1/auth/merchant/kakao/login",
        "/pg-auth-service/api/v1/auth/login/oauth2/code/kakao",
        "/pg-auth-service/api/v1/auth/token/refresh",
        "/pg-auth-service/api/v1/auth/admin/login",
        "/pg-auth-service/api/v1/auth/merchant/terms/agree",
        "/pg-auth-service/api/v1/auth/merchant/signup",

        // ── payment-service: QR 흐름 ──
        // /qr/request : 가맹점 QR 생성 (현 시점 API Key 발급 체계 미비, 테스트 진행을 위해 WL)
        // /qr/validate: 사용자 스캔 직후 호출, 프론트가 인증 헤더 미전송
        "/payment-service/api/v1/payment/qr/request",
        "/payment-service/api/v1/payment/qr/validate",

        // ── payment-service: 가맹점 SDK ──
        // Authorization 값은 JWT가 아니라 가맹점 API Key. 다운스트림 MerchantApiKeyResolver가 검증.
        "/payment-service/api/v1/merchant/payments"
    );

    // PG(pg-auth-service / merchant-service) 라우트 prefix.
    // 이 prefix로 시작하는 경로는 pgKey로 토큰을 검증한다.
    private static final List<String> PG_PATH_PREFIXES = List.of(
        "/pg-auth-service/",
        "/merchant-service/"
    );

    // 키 초기화 메서드
    @PostConstruct
    private void init() {
        System.out.println(">>>> JWT 인증 시크릿 키(user) : " + userSecret);
        System.out.println(">>>> JWT 인증 시크릿 키(pg)   : " + pgSecret);

        if (pgSecret == null || pgSecret.isBlank()) {
            throw new IllegalStateException("PG_JWT_SECRET 환경변수가 설정되지 않았습니다.");
        }

        // HMAC SHA 알고리즘을 사용해 키 생성
        this.userKey = Keys.hmacShaKeyFor(userSecret.getBytes(StandardCharsets.UTF_8));
        this.pgKey   = Keys.hmacShaKeyFor(pgSecret.getBytes(StandardCharsets.UTF_8));
    }

    // 필터 메서드
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println(">>>> JWT 인증 필터 시작");

        // 0. CORS preflight(OPTIONS) 통과: Authorization 헤더가 없는 게 정상이므로 검증 스킵
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            System.out.println(">>>> OPTIONS preflight 요청 - 토큰 검증 없이 통과");
            return chain.filter(exchange);
        }

        // 1. Authorization 헤더 추출
        System.out.println(">>>> 1. Authorization 헤더");
        // Bearer 토큰 추출
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        System.out.println(">>>>>> 1) 토큰 추출(bearerToken) : " + bearerToken);

        // 엔드포인트 추출 (ex. /billing-key-service/api/v1/billing-key/issue)
        String endPoint = exchange.getRequest().getURI().getRawPath();
        System.out.println(">>>>>> 2) 사용자 엔드포인트 추출 : " + endPoint);

        // HTTP 메서드 추출
        String method = exchange.getRequest().getMethod().name();
        System.out.println(">>>>>> 3) 요청 메서드 : " + method);

        // 2. 화이트리스트 경로 여부 확인 (prefix 매칭)
        System.out.println(">>>> 2) 화이트리스트 경로 여부 확인");
        if (WHITE_LIST_PATHS.stream().anyMatch(endPoint::startsWith)) {
            System.out.println(">>>>>> 1) 화이트리스트 경로이므로 토큰 검증 없이 통과 : " + endPoint);
            return chain.filter(exchange);
        }
        System.out.println(">>>>>> 2) 화이트리스트 경로가 아니므로 토큰 검증 수행 : " + endPoint);

        // 3. 라우트 prefix에 따라 검증기 분기
        // - PG_PATH_PREFIXES에 해당: pg-auth-service 토큰 규약(tokenType/accountId/role)
        // - 그 외: auth-service 토큰 규약(type/sub/status)
        if (PG_PATH_PREFIXES.stream().anyMatch(endPoint::startsWith)) {
            System.out.println(">>>> 3. PG JWT 검증 (pg-auth-service 발급 토큰)");
            return verifyPgAndForward(exchange, chain, bearerToken);
        }

        System.out.println(">>>> 3. User JWT 검증 (auth-service 발급 토큰)");
        return verifyUserAndForward(exchange, chain, bearerToken);
    }

    // auth-service 토큰 검증 → X-User-Id, X-User-Status 헤더 주입
    private Mono<Void> verifyUserAndForward(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String bearerToken) {
        try {
            // 토큰이 없거나 Bearer 토큰이 아닌 경우 예외 처리
            if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
                System.out.println(">>>>>> 1) 토큰이 없거나 Bearer 토큰이 아님 : " + bearerToken);
                throw new RuntimeException("JWT 인증 필터 토큰 예외");
            }

            // 토큰 값만 추출 (Bearer 제거)
            String token = bearerToken.substring(7);
            System.out.println(">>>> User JWT 인증 필터 - 토큰 : " + token);

            // JWT 토큰 검증 및 Claims 추출 (jjwt 0.12.x API)
            Claims claims = Jwts.parser()
                    .verifyWith(userKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // type 클레임 검증: ACCESS 토큰만 통과, REFRESH는 거부
            // (REFRESH는 /auth/refresh 같은 재발급 용도로만 사용되어야 함)
            String type = claims.get("type", String.class);
            System.out.println(">>>> User JWT 인증 필터 - claims get type : " + type);
            if (!"ACCESS".equals(type)) {
                System.out.println(">>>>>> ACCESS 토큰이 아님 (type=" + type + ") - 거부");
                throw new RuntimeException("ACCESS 토큰이 아님");
            }

            // subject (auth-service에서 userId(Long)를 String으로 변환해서 넣음)
            String userId = claims.getSubject();
            System.out.println(">>>> User JWT 인증 필터 - claims get userId(subject) : " + userId);

            // subject 없는 ACCESS 토큰은 거부
            // (X-User-Id를 null/빈 값으로 전달하면 다운스트림이 이를 신뢰된 인증 ID로 처리하므로 위험)
            if (userId == null || userId.isBlank()) {
                System.out.println(">>>>>> ACCESS 토큰에 subject가 없음 - 거부");
                throw new RuntimeException("ACCESS 토큰에 subject(userId)가 없음");
            }

            // status 클레임 (사용자 상태, 검증 없이 헤더로 전달만)
            String status = claims.get("status", String.class);
            System.out.println(">>>> User JWT 인증 필터 - claims get status : " + status);

            // 다운스트림 서비스로 사용자 정보 전달 (X- prefix는 custom header 관례)
            ServerWebExchange modifyExchange = exchange.mutate()
                    .request(builder -> builder
                            .header("X-User-Id", userId)
                            .header("X-User-Status", status == null ? "" : status)
                    ).build();
            return chain.filter(modifyExchange);

        } catch (Exception e) {
            e.printStackTrace();
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    // pg-auth-service 토큰 검증 → X-Account-Id, X-Account-Role 헤더 주입
    // 클레임 규약(JwtService.java 참고): accountId(Long), role(MERCHANT/PG_ADMIN), tokenType(ACCESS/REFRESH/SIGNUP)
    private Mono<Void> verifyPgAndForward(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String bearerToken) {
        try {
            if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
                System.out.println(">>>>>> 1) PG: 토큰이 없거나 Bearer 토큰이 아님 : " + bearerToken);
                throw new RuntimeException("PG JWT 인증 필터 토큰 예외");
            }

            String token = bearerToken.substring(7);
            System.out.println(">>>> PG JWT 인증 필터 - 토큰 : " + token);

            Claims claims = Jwts.parser()
                    .verifyWith(pgKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // tokenType 클레임 검증: ACCESS 토큰만 통과
            // REFRESH는 /auth/token/refresh(WL) 전용, SIGNUP은 가입 흐름(WL) 전용
            String tokenType = claims.get("tokenType", String.class);
            System.out.println(">>>> PG JWT 인증 필터 - claims get tokenType : " + tokenType);
            if (!"ACCESS".equals(tokenType)) {
                System.out.println(">>>>>> PG: ACCESS 토큰이 아님 (tokenType=" + tokenType + ") - 거부");
                throw new RuntimeException("PG ACCESS 토큰이 아님");
            }

            // accountId 클레임 (pg-auth-service에서 Long으로 넣음)
            Long accountId = claims.get("accountId", Long.class);
            System.out.println(">>>> PG JWT 인증 필터 - claims get accountId : " + accountId);
            if (accountId == null) {
                System.out.println(">>>>>> PG: accountId 없음 - 거부");
                throw new RuntimeException("PG ACCESS 토큰에 accountId 없음");
            }

            // role 클레임 (MERCHANT | PG_ADMIN)
            String role = claims.get("role", String.class);
            System.out.println(">>>> PG JWT 인증 필터 - claims get role : " + role);
            if (role == null || role.isBlank()) {
                System.out.println(">>>>>> PG: role 없음 - 거부");
                throw new RuntimeException("PG ACCESS 토큰에 role 없음");
            }

            // 다운스트림 서비스로 가맹점/관리자 정보 전달
            ServerWebExchange modifyExchange = exchange.mutate()
                    .request(builder -> builder
                            .header("X-Account-Id", String.valueOf(accountId))
                            .header("X-Account-Role", role)
                    ).build();
            return chain.filter(modifyExchange);

        } catch (Exception e) {
            e.printStackTrace();
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

}
