package com.sample.ldap.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${ldap.urls}")
	private String ldapUrls;

	@Value("${ldap.base.dn}")
	private String ldapBaseDn;

	@Value("${ldap.username}")
	private String ldapSecurityPrincipal;

	@Value("${ldap.password}")
	private String ldapPrincipalPassword;

	@Value("${ldap.user.dn.pattern}")
	private String ldapUserDnPattern;

	@Autowired
	LdapAuthenticationProvider ldapAuthenticationProvider;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable()
				.formLogin().disable().httpBasic().disable().authorizeRequests().antMatchers("/login").permitAll()
				.anyRequest().authenticated();
		
		 http.
      	sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER).maximumSessions(1).sessionRegistry(sessionRegistry()).and()
			.sessionFixation().migrateSession();

	}

	@Bean
	public HttpSessionIdResolver httpSessionStrategy() {
		return new HeaderHttpSessionIdResolver("token");
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(ldapAuthenticationProvider);
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Bean
	SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

}
