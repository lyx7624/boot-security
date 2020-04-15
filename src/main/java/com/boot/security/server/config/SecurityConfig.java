package com.boot.security.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.boot.security.server.filter.TokenFilter;

/**
* 功能描述: Security核心配置类
* 版本信息: Copyright (c)2019
* 公司信息: 智辰云科
* 开发人员: lyx
* 版本日志: 1.0
* 创建日期: 2019/8/1 17:09
*/
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;
	@Autowired
	private LogoutSuccessHandler logoutSuccessHandler;
	@Autowired
	private AuthenticationEntryPoint authenticationEntryPoint;
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private TokenFilter tokenFilter;

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//禁用csrf
		http.csrf().disable();

		// 基于token，所以不需要session
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		/*放行静态资源*/
		http.authorizeRequests()
				.antMatchers("/", "/*.html", "/favicon.ico", "/css/**", "/js/**", "/fonts/**", "/layui/**", "/img/**",
						"/v2/api-docs/**", "/swagger-resources/**", "/webjars/**", "/pages/**", "/druid/**",
						"/statics/**")
				.permitAll().anyRequest().authenticated();
		/*设置login界面及后续handler*/
		http.formLogin().loginPage("/login.html").loginProcessingUrl("/login")
				.successHandler(authenticationSuccessHandler).failureHandler(authenticationFailureHandler).and()
				.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
		/*退出登录*/
		http.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
		/*	 解决不允许显示在iframe的问题*/
		http.headers().frameOptions().disable();
		http.headers().cacheControl();

		/*添加到filter中 tokenFilter生效*/
		http.addFilterBefore(tokenFilter, UsernamePasswordAuthenticationFilter.class);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		/*用户认证类和加密方式*/
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
	}

}
