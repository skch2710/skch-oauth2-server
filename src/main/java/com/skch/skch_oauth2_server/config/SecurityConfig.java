package com.skch.skch_oauth2_server.config;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final AppProps appProps;
	
	private final CustomBearerTokenAuthenticationEntryPoint customBearerTokenAuthenticationEntryPoint;

	private final CustomBearerTokenAccessDeniedHandler customBearerTokenAccessDeniedHandler;
	
	// Authorization Server filter chain
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurity(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authServerConfig = new OAuth2AuthorizationServerConfigurer();
		http.securityMatcher(authServerConfig.getEndpointsMatcher())
				.with(authServerConfig, Customizer.withDefaults()).csrf(csrf -> csrf.disable());
		return http.build();
	}

	// Resource Server (API) filter chain
	@Bean
	@Order(2)
	public SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/actuator/**","/swagger-ui/**", "/v3/api-docs/**").permitAll()
						.anyRequest().authenticated())
		.oauth2ResourceServer(resourceServer -> resourceServer
				.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
				.authenticationEntryPoint(customBearerTokenAuthenticationEntryPoint)
				.accessDeniedHandler(customBearerTokenAccessDeniedHandler));
		return http.build();
	}

	private JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
		return jwtAuthenticationConverter;
	}

	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(appProps.getClientId())
				.clientSecret(appProps.getClientSecret())
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("read").scope("write")
				.clientSettings(
						ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
				.tokenSettings(TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(appProps.getTokenExpireIn())).build()).build();
		return new InMemoryRegisteredClientRepository(oidcClient);
	}

//	@Bean
//	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
//		return new JdbcRegisteredClientRepository(jdbcTemplate);
//	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			Authentication principal = context.getPrincipal();
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				Set<String> authorities = new HashSet<>(Set.of("TEST-R", "TEST-W", "TEST-X"));
				context.getClaims()
						.claim("authorities", authorities)
						.claim("user_name", principal.getName());
			}
		};
	}
}


/*
@Bean
@Primary
RegisteredClientRepository registeredClientRepository(
        JdbcTemplate jdbcTemplate,
        PasswordEncoder passwordEncoder) {

    JdbcRegisteredClientRepository repository = 
        new JdbcRegisteredClientRepository(jdbcTemplate);

    // Create client with proper settings
    RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("sathish_ch")
        .clientSecret(passwordEncoder.encode("sathish_ch@1234"))
        .clientName("Internal OAuth Client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("read")
        .scope("write")
        .clientSettings(ClientSettings.builder()
            .requireProofKey(true)
            .requireAuthorizationConsent(false)
            .build())
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .refreshTokenTimeToLive(Duration.ofHours(6))
            .reuseRefreshTokens(false)
            .build())
        .build();
    repository.save(client);
    return repository;
}

@Bean
OAuth2AuthorizationService authorizationService(
        JdbcTemplate jdbcTemplate,
        RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
}


@Bean
AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
}

*/
