package com.skch.skch_oauth2_server.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * The Class GlobalExceptionHandler.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * Custom exception handle.
     */
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<ErrorResponse> handleCustomException(CustomException ex, WebRequest request) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(ex.getStatus().value());
        response.setSuccessMessage(ex.getStatus().name());
        response.setErrorMessage(ex.getMessage());
        return new ResponseEntity<>(response, ex.getStatus());
    }

    /**
     * Access Denied Exception handle.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException edx) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN.value());
        response.setSuccessMessage("ACCESS_DENIED");
        response.setErrorMessage(edx.getMessage());
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    /**
     * Forbidden Exception handle.
     */
    @ExceptionHandler(org.springframework.web.client.HttpClientErrorException.Forbidden.class)
    public ResponseEntity<ErrorResponse> handleForbiddenException(org.springframework.web.client.HttpClientErrorException.Forbidden edx) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN.value());
        response.setSuccessMessage("FORBIDDEN");
        response.setErrorMessage(edx.getMessage());
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    /**
     * Invalid Bearer Token Exception handle.
     */
    @ExceptionHandler(InvalidBearerTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidBearerTokenException(InvalidBearerTokenException edx) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED.value());
        response.setSuccessMessage("Invalid access token.");
        response.setErrorMessage(edx.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Insufficient Authentication Exception handle.
     */
    @ExceptionHandler(InsufficientAuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleInsufficientAuthenticationException(InsufficientAuthenticationException edx) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED.value());
        response.setSuccessMessage("Full authentication is required to access this resource.");
        response.setErrorMessage(edx.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Missing CSRF Token Exception handle.
     */
    @ExceptionHandler(MissingCsrfTokenException.class)
    public ResponseEntity<ErrorResponse> handleMissingCsrfTokenException(MissingCsrfTokenException edx) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED.value());
        response.setSuccessMessage("CSRF token is missing.");
        response.setErrorMessage(edx.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Invalid CSRF Token Exception handle.
     */
    @ExceptionHandler(InvalidCsrfTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCsrfTokenException(InvalidCsrfTokenException edx) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED.value());
        response.setSuccessMessage("Invalid CSRF token.");
        response.setErrorMessage(edx.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }
    

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {

		Map<String, String> errors = new HashMap<>();
		ex.getBindingResult().getFieldErrors()
				.forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));

		ErrorResponse response = new ErrorResponse();
		response.setStatusCode(HttpStatus.BAD_REQUEST.value());
		response.setSuccessMessage("Invalid Request.");
		response.setErrorMessage(errors.toString());

		return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
	}



    /**
     * Generic Exception handle.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setSuccessMessage("An unexpected error occurred.");
        response.setErrorMessage(ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
