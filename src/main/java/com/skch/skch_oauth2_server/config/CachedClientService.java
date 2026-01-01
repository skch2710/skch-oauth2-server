package com.skch.skch_oauth2_server.config;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
public class CachedClientService {

	private final Map<String, RegisteredClient> clientCache = new ConcurrentHashMap<>();
	private final RegisteredClientRepository repository;

	public CachedClientService(RegisteredClientRepository repository) {
		this.repository = repository;
	}

	public RegisteredClient getClient(String clientId) {
		return clientCache.computeIfAbsent(clientId, id -> repository.findByClientId(id));
	}
}
