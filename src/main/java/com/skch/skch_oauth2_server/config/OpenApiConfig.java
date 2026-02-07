package com.skch.skch_oauth2_server.config;

import java.util.ArrayList;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.skch.skch_oauth2_server.common.Constant;

import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.models.parameters.Parameter;

@Configuration
public class OpenApiConfig {

	@Bean
	public OpenApiCustomizer globalHeaderCustomizer() {
		return openApi -> {
			Parameter headerParam = new Parameter().in(ParameterIn.HEADER.toString())
					.name(Constant.REQUEST_HEADER_NAME).required(true);
			openApi.getPaths().forEach((path, pathItem) -> {
				pathItem.readOperations().forEach(operation -> {
					if (operation.getParameters() == null) {
						operation.setParameters(new ArrayList<>());
					}
					boolean exists = operation.getParameters().stream()
							.anyMatch(p -> Constant.REQUEST_HEADER_NAME.equals(p.getName()));
					if (!exists) {
						operation.getParameters().add(headerParam);
					}
				});
			});
		};
	}
}
