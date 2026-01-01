package com.skch.skch_oauth2_server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.skch.skch_oauth2_server.service.JpaUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Value("${app.client-id}")
	private String clientId;
	
	@Value("${app.client-cred}")
	private String clientCred;
	
	@Value("${app.expire-time}")
	private Long expireTime;
	
	@Autowired
	private JpaUserDetailsManager jpaUserDetailsManager;

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
				OAuth2AuthorizationServerConfigurer.authorizationServer();
		http.securityMatcher(
			authorizationServerConfigurer.getEndpointsMatcher()).with(
				authorizationServerConfigurer, (
					authorizationServer) -> authorizationServer.oidc(Customizer.withDefaults())
						.tokenEndpoint(tokenEndpoint -> tokenEndpoint
						.accessTokenRequestConverter(new CustomGrantAuthenticationConverter())
						.authenticationProvider(new CustomGrantAuthenticationProvider(
							oAuth2AuthorizationService(), tokenGenerator(),
							userDetailsService(), passwordEncoder()))));
		http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint("/login"), 
				new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
				.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@Bean 
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults());
		return http.build();
	}

	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	UserDetailsManager userDetailsService() {
		return jpaUserDetailsManager;
	}

	@Bean 
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId)
				.clientSecret(clientCred)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(new AuthorizationGrantType("custom_pwd"))
				.redirectUri("http://127.0.0.1:8080/login/oauth2")
				.postLogoutRedirectUri("http://127.0.0.1:8080/")
				.scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
				.scope("read").scope("write")
				.clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
				.tokenSettings(TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(expireTime))
						.refreshTokenTimeToLive(Duration.ofHours(expireTime))
						.reuseRefreshTokens(false) // set to false to issue a new refresh token upon use
						.build())
				.build();
		return new InMemoryRegisteredClientRepository(oidcClient);
	}

	@Bean 
	JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() { 
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean 
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean 
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	OAuth2AuthorizationService oAuth2AuthorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}
	
	@Bean
	OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(tokenCustomizer());
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}
	
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			Authentication principal = context.getPrincipal();
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toSet());
				context.getClaims().claim("authorities", authorities)
				.claim("user_name", principal.getName())
				.claim("client_id", context.getRegisteredClient().getClientId());
			}
			
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toSet());
				context.getClaims().claim("authorities", authorities);
			}
		};
	}
}
