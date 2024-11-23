package com.skch.skch_oauth2_server.model;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "roles", schema = "hostel")
public class Roles {
	
	@Id
    @Column(name = "role_id")
    private Long roleId;
    
    @Column(name = "role_name", nullable = false)
    private String roleName;
    
    @Column(name = "is_active")
    private boolean isActive;
    
    @Column(name = "is_external_role")
    private boolean isExternalRole;
    
    @Column(name = "note", columnDefinition = "text")
    private String note;
    
    @Column(name = "created_by_id")
    private Long createdById;
    
    @Column(name = "created_date")
    private Date createdDate;
    
    @Column(name = "modified_by_id")
    private Long modifiedById;
    
    @Column(name = "modified_date")
    private Date modifiedDate;

}
