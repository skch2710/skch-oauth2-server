package com.skch.skch_oauth2_server.service;

import java.util.Collection;
import java.util.HashSet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import com.skch.skch_oauth2_server.dao.UsersDAO;
import com.skch.skch_oauth2_server.model.UserPrivilege;
import com.skch.skch_oauth2_server.model.Users;
import com.skch.skch_oauth2_server.util.AESUtils;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class JpaUserDetailsManager implements UserDetailsManager {

	@Autowired
	private UsersDAO userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Users user = userRepository.findByEmailIdIgnoreCase(username);
		User ur = null;
		try {
			if (!user.getEmailId().equalsIgnoreCase(username)) {
				throw new UsernameNotFoundException("Access Denied");
			}
			Collection<GrantedAuthority> authoriies = new HashSet<>();
			authoriies.add(new SimpleGrantedAuthority(user.getUserRole().getRoles().getRoleName()));
			
			authoriies.add(new SimpleGrantedAuthority("USER UUID : "+user.getUserUuid()));
			
			authoriies.add(new SimpleGrantedAuthority("USER_ID : "+ AESUtils.encrypt(user.getUserId().toString())));

			for (UserPrivilege privileges : user.getUserPrivilege()) {
				String resourceName = privileges.getResource().getResourceName();
				if (privileges.getReadOnlyFlag()) {
					String readOnly = resourceName + "-R";
					authoriies.add(new SimpleGrantedAuthority(readOnly));
				}else if (privileges.getReadWriteFlag()) {
					String readWriteOnly = resourceName + "-W";
					authoriies.add(new SimpleGrantedAuthority(readWriteOnly));
				}else if (privileges.getTerminateFlag()) {
					String terminate = resourceName + "-X";
					authoriies.add(new SimpleGrantedAuthority(terminate));
				}
			}
			ur = new User(user.getEmailId(), user.getPasswordSalt(), authoriies);
		} catch (Exception e) {
			log.error("Error in loadUserByUsername :: ", e);
		}
		return ur;
	}

	@Override
	public void createUser(UserDetails user) {
	}

	@Override
	public void updateUser(UserDetails user) {
	}

	@Override
	public void deleteUser(String username) {
	}

	@Override
	public void changePassword(String oldPassword, String newPassword) {
	}

	@Override
	public boolean userExists(String username) {
		Users user = userRepository.findByEmailIdIgnoreCase(username);
		if(user.getEmailId().equalsIgnoreCase(username)) {
			return true;
		}
		return false;
	}

}
