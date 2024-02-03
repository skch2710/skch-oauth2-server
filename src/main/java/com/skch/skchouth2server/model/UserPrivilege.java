package com.skch.skchouth2server.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "user_privileges", schema = "hostel")
@JsonIgnoreProperties(ignoreUnknown = true, value = { "users" })
public class UserPrivilege {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_privileges_id")
    private Long userPrivilegesId;

    @ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "user_id", nullable = true)
	private Users users;

    @OneToOne
	@JoinColumn(name = "resource_id", nullable = true)
	private Resource resource;

    @Column(name = "read_only_flag")
    private Boolean readOnlyFlag;

    @Column(name = "read_write_flag")
    private Boolean readWriteFlag;

    @Column(name = "terminate_flag")
    private Boolean terminateFlag;

    @Column(name = "is_active")
    private Boolean isActive;

    @Column(name = "created_by_id")
    private Long createdById;

    @Column(name = "created_date")
    private Date createdDate;

    @Column(name = "modified_by_id")
    private Long modifiedById;

    @Column(name = "modified_date")
    private Date modifiedDate;
}
