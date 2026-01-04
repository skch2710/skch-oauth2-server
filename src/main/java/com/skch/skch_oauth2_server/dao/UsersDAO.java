package com.skch.skch_oauth2_server.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.skch.skch_oauth2_server.model.Users;

import jakarta.transaction.Transactional;

@Repository
public interface UsersDAO extends JpaRepository<Users, Long> {

	Users findByEmailIdIgnoreCase(String emailId);
	
	Users findByUserId(Long userId);
	
	@Modifying
	@Transactional
	@Query(value = "DELETE FROM public.oauth2_authorization"
			+  " WHERE (access_token_expires_at IS NOT NULL AND access_token_expires_at < NOW())"
			+ " OR (authorization_code_expires_at IS NOT NULL AND authorization_code_expires_at < NOW())", nativeQuery = true)
	void clearExpiredTokens();

}
