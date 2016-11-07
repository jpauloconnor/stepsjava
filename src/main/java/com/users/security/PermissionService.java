package com.users.security;

import static com.users.security.Role.ROLE_ADMIN;
import static com.users.security.Role.ROLE_USER;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.users.beans.User;
import com.users.repositories.ContactRepository;
import com.users.repositories.UserRepository;

@Service
public class PermissionService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private ContactRepository contactRepository;

	private AbstractAuthenticationToken getToken() {
		return (AbstractAuthenticationToken) getContext().getAuthentication();
	}


	public long findCurrentUserId() {
		List<User> users = userRepository.findByEmail(getToken().getName());
		return users != null && !users.isEmpty() ? users.get(0).getId() : -1;
	}


	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	public boolean canAccessUser(long userId) {
		return hasRole(ROLE_ADMIN) || (hasRole(ROLE_USER) && findCurrentUserId() == userId);
	}

	public boolean canEditContact(long contactId) {
		return hasRole(ROLE_USER)
				&& contactRepository.findByUserIdAndId(findCurrentUserId(), contactId) != null;
	}

}