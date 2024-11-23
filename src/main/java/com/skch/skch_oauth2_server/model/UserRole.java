package com.skch.skch_oauth2_server.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "user_roles", schema = "hostel")
@JsonIgnoreProperties(ignoreUnknown = true, value = { "users" })
public class UserRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_role_id")
    private Long userRoleId;

    @OneToOne
	@JoinColumn(name = "user_id", nullable = true)
	private Users users;

    @OneToOne
	@JoinColumn(name = "role_id", nullable = true)
	private Roles roles;

    @Column(name = "is_active")
    private boolean isActive;

    @Column(name = "created_by_id")
    private Long createdById;

    @Column(name = "created_date")
    private Date createdDate;

    @Column(name = "modified_by_id")
    private Long modifiedById;

    @Column(name = "modified_date")
    private Date modifiedDate;
}
