package com.skch.skch_oauth2_server.model;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "users", schema = "hostel")
public class Users {

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "email_id", nullable = false, unique = true)
    private String emailId;

    @Column(name = "password_salt")
    private String passwordSalt;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "dob")
    private LocalDate dob;

    @Column(name = "mail_uuid", length = 150)
    private String mailUuid;

    @Column(name = "user_uuid", length = 150)
    private String userUuid;

    @Column(name = "is_active")
    private boolean isActive;

    @Column(name = "last_login_date")
    private LocalDateTime lastLoginDate;

    @Column(name = "last_password_reset_date")
    private LocalDateTime lastPasswordResetDate;
    
    @OneToOne(fetch = FetchType.EAGER, mappedBy = "users", cascade = CascadeType.ALL)
	private UserRole userRole;
    
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "users", cascade = CascadeType.ALL)
	private List<UserPrivilege> userPrivilege;

    @Column(name = "created_by_id")
    private Long createdById;

    @Column(name = "created_date")
    private Date createdDate;

    @Column(name = "modified_by_id")
    private Long modifiedById;

    @Column(name = "modified_date")
    private Date modifiedDate;

}
