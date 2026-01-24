package com.skch.skch_oauth2_server.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Configuration
@ConfigurationProperties(prefix = "app")
@Getter
@Setter
public class AppProps {
	
	private String clientId;
	private String clientSecret;
	private long tokenExpireIn;
	private String headerKey;
	private List<String> allowHeaders;

}
