package com.skch.skchouth2server.model;

import java.util.Date;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.Data;

@Entity
@Data
@Table(name="employees",schema="login")
public class Employee{

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long empId;
	
	private String emailId;
	
	private String firstName;
	
	private String lastName;
	
	private String passwordSalt;
	
	@OneToOne(fetch = FetchType.EAGER, mappedBy = "employee", cascade = CascadeType.ALL)
	private EmployeeRole employeeRole;
	
	@Transient
	private String otp;
	
	private Long createdById;
	
	private Date createdDate;
	
	private Long modifiedById;
	
	private Date modifiedDate;
}
