/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example;

import org.springframework.context.annotation.Bean;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Basic security resource server.
 *
 * @author Rob Winch
 * @since 5.1
 */
@EnableWebFluxSecurity
public class SecurityConfiguration {

	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		// @formatter:off
		http
			.authorizeExchange((authorize) -> authorize
				.pathMatchers(HttpMethod.GET, "/message/**").hasAuthority("SCOPE_message:read")
				.pathMatchers(HttpMethod.POST, "/message/**").hasAuthority("SCOPE_message:write")
				.anyExchange().authenticated()
			)
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(withDefaults())
			);
		// @formatter:on
		return http.build();
	}

	@Bean
	static ReactiveJwtDecoder reactiveJwtDecoder() {
		NimbusReactiveJwtDecoder result = new NimbusReactiveJwtDecoder("http://localhost:9000/oauth2/jwks");
		return new ReactiveJwtDecoder() {
			@Override
			public Mono<Jwt> decode(String token) throws JwtException {
				return result.decode(token)
						.flatMap(jwt -> enrich(token, jwt));
			}

			private Mono<Jwt> enrich(String token, Jwt jwt) {
				WebClient webClient = WebClient.create();

				return webClient.get()
						.uri("http://localhost:9000/oauth2/userinfo")
						.headers(headers -> headers.setBearerAuth(token))
						.retrieve()
						.bodyToMono(new ParameterizedTypeReference<Map<String,String>>() {})
						.map(userInfo ->
							Jwt.withTokenValue(jwt.getTokenValue())
									.subject(jwt.getSubject())
									.audience(jwt.getAudience())
									.headers(headers -> headers.putAll(jwt.getHeaders()))
									.claims(claims -> claims.putAll(userInfo))
									.claims(claims -> claims.putAll(jwt.getClaims()))
									.build()
						);
			}
		};
	}
}
