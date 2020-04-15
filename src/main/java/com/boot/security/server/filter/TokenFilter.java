package com.boot.security.server.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.boot.security.server.dto.LoginUser;
import com.boot.security.server.service.TokenService;

/**
* 功能描述: token过滤器
* 版本信息: Copyright (c)2019
* 公司信息: 智辰云科
* 开发人员: lyx
* 版本日志: 1.0
* 创建日期: 2019/8/1 17:01
*/
@Component
public class TokenFilter extends OncePerRequestFilter {


	private static final String TOKEN_KEY = "token";

	@Autowired
	private TokenService tokenService;
	@Autowired
	private UserDetailsService userDetailsService;
	/*一个时间数值*/
	private static final Long MINUTES_10 = 10 * 60 * 1000L;


	/**
	 * 功能描述：请求监听
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:53
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = getToken(request);
		if (StringUtils.isNotBlank(token)) {//判断token是否存在
			LoginUser loginUser = tokenService.getLoginUser(token);//获取到user
			if (loginUser != null) {
				loginUser = checkLoginTime(loginUser);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(loginUser,
						null, loginUser.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);//讲user放入SecurityContextHolder
			}
		}

		filterChain.doFilter(request, response);
	}


	/**
	 * 功能描述：登录时间校验，小于十分钟自动刷新有效时间
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:52
	 */
	private LoginUser checkLoginTime(LoginUser loginUser) {
		long expireTime = loginUser.getExpireTime();
		long currentTime = System.currentTimeMillis();
		if (expireTime - currentTime <= MINUTES_10) {
			String token = loginUser.getToken();
			loginUser = (LoginUser) userDetailsService.loadUserByUsername(loginUser.getUsername());
			loginUser.setToken(token);
			tokenService.refresh(loginUser);
		}
		return loginUser;
	}


	/**
	 * 功能描述：根据请求参数或者请求头获取token
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:52
	 */
	public static String getToken(HttpServletRequest request) {
		String token = request.getParameter(TOKEN_KEY);
		if (StringUtils.isBlank(token)) {
			token = request.getHeader(TOKEN_KEY);
		}

		return token;
	}

}
