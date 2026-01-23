package com.skch.skch_oauth2_server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.skch.skch_oauth2_server.model.JwtDTO;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@RequestMapping("/api/v1/test")
@SecurityRequirement(name = "bearerAuth")
public class TestController {
	
	@GetMapping("/testget/{test}")
	@Operation(summary="get test",description = "Return the result")
//	@PreAuthorize("hasAnyAuthority('Super User')")
//	@PreAuthorize("@jwtUtil.checkAccess(#p0)")
//	@PreAuthorize("hasAuthority(#p0)")
	public ResponseEntity<?> getNavTwo(@PathVariable("test") String test){
		return ResponseEntity.ok("Access :: "+test);
	}
	
	@PostMapping("/test-post")
	@Operation(summary="test post",description = "Return the result post")
//	@PreAuthorize("hasAnyAuthority(#p0.getTest())")
//	@PreAuthorize("@jwtUtil.checkAccess(#p0.getResource())")
	public ResponseEntity<?> getNav(@RequestBody JwtDTO jwtDTO){
		return ResponseEntity.ok("Access :: "+jwtDTO);
	}

}
