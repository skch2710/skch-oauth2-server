package com.skch.skch_oauth2_server.config;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.skch.skch_oauth2_server.model.Users;
import com.skch.skch_oauth2_server.service.CustomUserDetails;
import com.skch.skch_oauth2_server.util.AESUtils;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Value("${app.grant-type}")
	private String grantType;

    // =========================================================
    // 1️⃣ Authorization Server Security
    // =========================================================
	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			OAuth2AuthorizationService authorizationService, 
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
			UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
				OAuth2AuthorizationServerConfigurer.authorizationServer();
		http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.csrf(csrf -> csrf.ignoringRequestMatchers(
						authorizationServerConfigurer.getEndpointsMatcher()))
				.exceptionHandling(
						ex -> ex.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
				.with(authorizationServerConfigurer, server -> {
					server.oidc(Customizer.withDefaults());
					server.tokenEndpoint(tokenEndpoint -> tokenEndpoint
							.accessTokenRequestConverter(
									new CustomGrantAuthenticationConverter(grantType))
							.authenticationProvider(
									new CustomGrantAuthenticationProvider(authorizationService,
									tokenGenerator, userDetailsService, passwordEncoder)));
				});
		return http.build();
	}


    // =========================================================
    // 2️⃣ Default Login (Form Login)
    // =========================================================
    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    // =========================================================
    // 3️⃣ Password Encoder
    // =========================================================
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // =========================================================
    // 4️⃣ Registered Clients (JDBC)
    // =========================================================
    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    // =========================================================
    // 5️⃣ Authorization Persistence (JDBC)
    // =========================================================
    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    // =========================================================
    // 6️⃣ Authorization Server Settings
    // =========================================================
    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    // =========================================================
    // 8️⃣ JWT Decoder (internal)
    // =========================================================
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // =========================================================
    // 9️⃣ Token Generator
    // =========================================================
	@Bean
	OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		jwtGenerator.setJwtCustomizer(tokenCustomizer());
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2AccessTokenGenerator(),
				new OAuth2RefreshTokenGenerator());
	}

    // =========================================================
    // 🔟 Custom JWT Claims
    // =========================================================
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims()
                        .claim("authorities", authorities)
                        .claim("user_name", principal.getName())
                        .claim("sid", UUID.randomUUID().toString());
                // Try to extract the JPA Users entity if present on the principal
                if (principal.getPrincipal() instanceof CustomUserDetails) {
                    Users u = ((CustomUserDetails) principal.getPrincipal()).getUsers();
                    if (u != null && u.getUserRole() != null && u.getUserRole().getRoles() != null) {
                        context.getClaims().claim("user_role", u.getUserRole().getRoles().getRoleName());
                    }
                    if(u != null) {
						context.getClaims().claim("uid", AESUtils.encrypt(u.getUserId().toString()));
					}
                }
            }
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities);
            }
        };
    }
}