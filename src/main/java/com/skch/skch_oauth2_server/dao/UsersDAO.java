package com.skch.skch_oauth2_server.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.skch.skch_oauth2_server.model.Users;

public interface UsersDAO extends JpaRepository<Users, Long> {

	Users findByEmailIdIgnoreCase(String emailId);
	
	Users findByUserId(Long userId);

}
