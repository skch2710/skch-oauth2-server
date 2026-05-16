package com.skch.skch_oauth2_server.service;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.skch.skch_oauth2_server.model.Users;

public class CustomUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final Users users;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(Users users, Collection<? extends GrantedAuthority> authorities) {
        this.users = users;
        this.authorities = authorities;
    }

    public Users getUsers() {
        return users;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return users.getPasswordSalt();
    }

    @Override
    public String getUsername() {
        return users.getEmailId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return users.isActive();
    }

}
