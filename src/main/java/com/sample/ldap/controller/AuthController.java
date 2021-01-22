package com.sample.ldap.controller;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.sample.ldap.dto.AuthRequest;

@RestController
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private HttpSession session;

	@PostMapping("/login")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authenticationRequest) throws Exception {
		try {
			Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(), authenticationRequest.getPassword()));
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
		
		return ResponseEntity.ok(session.getId());
	}
}
