package com.erumpay.api_gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
	"jwt.secret=test-jwt-secret-key-must-be-at-least-256-bits-long-for-hs256",
	"pg.jwt.secret=test-pg-jwt-secret-key-must-be-at-least-256-bits-long-for-hs256"
})
class ApiGatewayApplicationTests {

	@Test
	void contextLoads() {
	}

}
