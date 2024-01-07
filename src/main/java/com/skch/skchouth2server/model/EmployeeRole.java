package com.skch.skchouth2server.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "emp_roles", schema = "login")
@JsonIgnoreProperties(ignoreUnknown = true, value = { "employee" })
public class EmployeeRole {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int empRoleId;

	@OneToOne
	@JoinColumn(name = "emp_id", nullable = true)
	private Employee employee;

	@ManyToOne
	@JoinColumn(name = "role_id", nullable = true)
	private Roles role;

	private Date roleStartDate;

	private Date roleEndDate;

	private boolean isActive;

	private Long createdById;

	private Date createdDate;

	private Long modifiedById;

	private Date modifiedDate;

}
