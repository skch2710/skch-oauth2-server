package com.skch.skchouth2server.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.skch.skchouth2server.model.Employee;

public interface EmployeeDAO extends JpaRepository<Employee, Long> {

	Employee findByEmailId(String emailId);
	
	Employee findByEmailIdIgnoreCase(String emailId);

}
