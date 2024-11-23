package com.skch.skch_oauth2_server.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "resource", schema = "hostel")
public class Resource {

    @Id
    @Column(name = "resource_id")
    private Long resourceId;

    @Column(name = "resource_name", length = 250)
    private String resourceName;

    @Column(name = "resource_path", length = 250)
    private String resourcePath;

    @Column(name = "icon", length = 250)
    private String icon;

    @Column(name = "display_order")
    private Long displayOrder;

    @Column(name = "is_subnav", length = 1)
    private String isSubnav;
    
    @Column(name = "parent_name")
    private String parentName;
    
    @Column(name = "parent_icon")
    private String parentIcon;

    @Column(name = "is_active")
    private boolean isActive;

}
