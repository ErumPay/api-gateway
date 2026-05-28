package com.erumpay.api_gateway;


import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import reactor.core.publisher.Mono;

@Component  // Spring Framework를 통해 객체 관리
public class JwtAuthFilter implements GlobalFilter {

    @Value("${jwt.secret}")
    private String secret;  // yml 파일에서 주입받은 JWT 시크릿 키 (auth-service와 동일해야 함)

    private SecretKey secretKey;

    // 토큰 검증 없이 통과하는 화이트리스트 등록 (prefix 매칭 — startsWith)
    // NOTE: 게이트웨이 경로 기준(StripPrefix 적용 전). 즉 /{service-name}/... 형태로 작성
    //       prefix 매칭이므로 하위 경로 모두 통과되는 점 주의
    private static final List<String> WHITE_LIST_PATHS = List.of(
        // ── 헬스체크 ──
        "/actuator/health",
        "/actuator/info",

        // ── auth-service: 로그인/토큰 재발급/SMS 등 인증 전 진입점 ──
        // NOTE: ACCESS 토큰 없이 호출되어야 하는 경로만 허용
        "/auth-service/api/auth/kakao/login",     // 카카오 로그인 (JWT 발급 전)
        "/auth-service/api/auth/token/refresh",   // ACCESS 재발급 (REFRESH 토큰으로 검증)
        "/auth-service/api/auth/sms",             // SMS 인증 (로그인 전 단계)
        "/auth-service/api/auth/dev",             // 개발용 토큰 발급 (운영 비노출 필요)

        // ── PG/시뮬레이터: 별도 인증(API Key/HMAC) 사용 가능성 ──
        // NOTE: 실제 인증 방식 확정 시 화이트리스트 범위 재조정
        "/pg-auth-service",                       // 가맹점-PG 인증 (서버 to 서버)
        "/pg-payment-service",                    // 가맹점→PG 결제 승인
        "/merchant-service",                      // 가맹점 콘솔/API
        "/card-simulator-service"                 // 테스트용 가상 카드사

        // ── 추가 검토 항목 (구현 시 활성화) ──
        // , "/notification-service/api/v1/notification/webhook"  // FCM/외부 webhook 콜백
    );

    // 키 초기화 메서드
    @PostConstruct
    private void init() {
        System.out.println(">>>> JWT 인증 시크릿 키 : " + secret);
        // HMAC SHA 알고리즘을 사용해 키 생성
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // 필터 메서드
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        System.out.println(">>>> JWT 인증 필터 시작");

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

        // 3. JWT 토큰 검증
        System.out.println(">>>> 3. JWT 토큰 검증");
        try {
            // 토큰이 없거나 Bearer 토큰이 아닌 경우 예외 처리
            if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
                System.out.println(">>>>>> 1) 토큰이 없거나 Bearer 토큰이 아님 : " + bearerToken);
                throw new RuntimeException("JWT 인증 필터 토큰 예외");
            }

            // 토큰 값만 추출 (Bearer 제거)
            String token = bearerToken.substring(7);
            System.out.println(">>>> JWT 인증 필터 - 토큰 : " + token);

            // JWT 토큰 검증 및 Claims 추출 (jjwt 0.12.x API)
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // type 클레임 검증: ACCESS 토큰만 통과, REFRESH는 거부
            // (REFRESH는 /auth/refresh 같은 재발급 용도로만 사용되어야 함)
            String type = claims.get("type", String.class);
            System.out.println(">>>> JWT 인증 필터 - claims get type : " + type);
            if (!"ACCESS".equals(type)) {
                System.out.println(">>>>>> ACCESS 토큰이 아님 (type=" + type + ") - 거부");
                throw new RuntimeException("ACCESS 토큰이 아님");
            }

            // subject (auth-service에서 userId(Long)를 String으로 변환해서 넣음)
            String userId = claims.getSubject();
            System.out.println(">>>> JWT 인증 필터 - claims get userId(subject) : " + userId);

            // subject 없는 ACCESS 토큰은 거부
            // (X-User-Id를 null/빈 값으로 전달하면 다운스트림이 이를 신뢰된 인증 ID로 처리하므로 위험)
            if (userId == null || userId.isBlank()) {
                System.out.println(">>>>>> ACCESS 토큰에 subject가 없음 - 거부");
                throw new RuntimeException("ACCESS 토큰에 subject(userId)가 없음");
            }

            // status 클레임 (사용자 상태, 검증 없이 헤더로 전달만)
            String status = claims.get("status", String.class);
            System.out.println(">>>> JWT 인증 필터 - claims get status : " + status);

            // 다운스트림 서비스로 사용자 정보 전달 (X- prefix는 custom header 관례)
            // NOTE: 헤더 이름은 user-service/auth-service 측 컨벤션과 일치해야 함
            //       다른 이름으로 합의된 경우 아래 .header(...) 부분만 교체하세요
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

}
