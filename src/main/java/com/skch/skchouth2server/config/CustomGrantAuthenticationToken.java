package com.skch.skchouth2server.config;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class CustomGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private static final long serialVersionUID = 1L;
	private final String username;
	private final String password;
	private final Set<String> scopes;

	protected CustomGrantAuthenticationToken(
			String granttype,
			Authentication clientPrincipal,@Nullable Set<String> scopes, 
			Map<String, Object> additionalParameters) {
		super(new AuthorizationGrantType(granttype), clientPrincipal, additionalParameters);
		this.username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
		this.password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);
		this.scopes = Collections.unmodifiableSet(
				scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
	}

	public String getUsername() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}
	
	public Set<String> getScopes() {
		return this.scopes;
	}

}
