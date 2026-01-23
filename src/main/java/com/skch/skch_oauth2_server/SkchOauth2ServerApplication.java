package com.skch.skch_oauth2_server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@SpringBootApplication
@EnableAsync
@OpenAPIDefinition(info = @Info(title = "Spring Boot", version = "3.4.0", description = "Oauth2 Server"))
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, bearerFormat = "JWT", scheme = "bearer")
public class SkchOauth2ServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SkchOauth2ServerApplication.class, args);
	}

}
