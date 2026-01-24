package com.skch.skch_oauth2_server.config;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class HeaderFilter extends OncePerRequestFilter {
	
	private final AppProps appProps;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String path = request.getRequestURI();
		
		if (path.startsWith("/actuator") || 
				path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs")) {
			filterChain.doFilter(request, response);
			return;
		}

		String headerValue = request.getHeader(appProps.getHeaderKey());

		if (headerValue == null || headerValue.isBlank() ||
				!appProps.getAllowHeaders().contains(headerValue) ) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());
			response.setContentType("application/json");
			response.getWriter().write("""
					{
					  "statusCode": 400,
					  "errorMessage": "Mandatory request header is missing or incorrect",
					  "successMessage": ""
					}
					""");
			return;
		}

		filterChain.doFilter(request, response);
	}
}
