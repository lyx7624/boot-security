package com.boot.security.server.service.impl;

import java.util.List;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.boot.security.server.dao.PermissionDao;
import com.boot.security.server.dto.LoginUser;
import com.boot.security.server.model.Permission;
import com.boot.security.server.model.SysUser;
import com.boot.security.server.model.SysUser.Status;
import com.boot.security.server.service.UserService;

/**
* 功能描述: 登录处理
* 版本信息: Copyright (c)2019
* 公司信息: 智辰云科
* 开发人员: lyx
* 版本日志: 1.0
* 创建日期: 2019/8/1 17:20
*/
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UserService userService;
	@Autowired
	private PermissionDao permissionDao;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//查询用户是否存在
		SysUser sysUser = userService.getUser(username);
		if (sysUser == null) {
			throw new AuthenticationCredentialsNotFoundException("用户名不存在");
		} else if (sysUser.getStatus() == Status.LOCKED) {
			throw new LockedException("用户被锁定,请联系管理员");
		} else if (sysUser.getStatus() == Status.DISABLED) {
			throw new DisabledException("用户已作废");
		}

		LoginUser loginUser = new LoginUser();
		BeanUtils.copyProperties(sysUser, loginUser);

		/*查询用户权限*/
		List<Permission> permissions = permissionDao.listByUserId(sysUser.getId());
		loginUser.setPermissions(permissions);

		return loginUser;
	}

}
