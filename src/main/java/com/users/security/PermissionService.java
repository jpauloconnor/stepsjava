package com.users.security;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;
import static com.users.security.Role.ADMIN;
import static com.users.security.Role.USER;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.users.repositories.UserRepository;

@Service
public class PermissionService {

	@Autowired
	private UserRepository userRepo;


	private UsernamePasswordAuthenticationToken getToken() {
		return (UsernamePasswordAuthenticationToken) getContext().getAuthentication();
	}
	
	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}
	
	public boolean canEditUser(long userId) {
		long currentUserId = userRepo.findByEmail(getToken().getName()).get(0).getId();
		return hasRole(ADMIN) || (hasRole(USER) && currentUserId == userId);
	}

	


}
