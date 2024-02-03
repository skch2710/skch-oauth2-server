package com.skch.skchouth2server.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.skch.skchouth2server.model.Users;

public interface UsersDAO extends JpaRepository<Users, Long> {

	Users findByEmailIdIgnoreCase(String emailId);
	
	Users findByUserId(Long userId);

}
