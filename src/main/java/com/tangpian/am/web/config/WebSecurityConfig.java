package com.tangpian.am.web.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import com.tangpian.am.model.Role;

@Configuration
@EnableWebSecurity
// @EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	// @Autowired
	// private TangpianUserDetailService tangpianUserDetailService;

	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/static/**", "/webjars/**", "/api/**", "/status/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/api/**").permitAll().anyRequest().authenticated()

				.and().formLogin().loginPage("/login").permitAll()

				.and().logout().permitAll()

				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.invalidSessionUrl("/login?invalid")

				// TODO CSRF临时禁用
				.and().csrf().disable();
		http.headers().frameOptions().sameOrigin();

	}

	@Autowired
	private DataSource dataSource;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("admin").password("password").authorities("ROLE_USER");
		// auth.jdbcAuthentication().dataSource(dataSource)
		// .usersByUsernameQuery(
		// "select id,password, enabled from user where username=?")
		// .authoritiesByUsernameQuery(
		// "select r.user_id, r.role_name from role r join user u on u.id =
		// r.user_id where u.id = ?");
	}

}
