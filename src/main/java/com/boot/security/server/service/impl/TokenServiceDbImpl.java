package com.boot.security.server.service.impl;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.alibaba.fastjson.JSONObject;
import com.boot.security.server.dao.TokenDao;
import com.boot.security.server.dto.LoginUser;
import com.boot.security.server.dto.Token;
import com.boot.security.server.model.TokenModel;
import com.boot.security.server.service.SysLogService;
import com.boot.security.server.service.TokenService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
* 功能描述: token实现类（存到数据库）
* 版本信息: Copyright (c)2019
* 公司信息: 智辰云科
* 开发人员: lyx
* 版本日志: 1.0
* 创建日期: 2019/8/1 17:49
*/
@Primary
@Service
public class TokenServiceDbImpl implements TokenService {

	private static final Logger log = LoggerFactory.getLogger("adminLogger");
	/**
	 * token过期秒数
	 */
	@Value("${token.expire.seconds}")
	private Integer expireSeconds;
	@Autowired
	private TokenDao tokenDao;
	@Autowired
	private SysLogService logService;
	/**
	 * 私钥
	 */
	@Value("${token.jwtSecret}")
	private String jwtSecret;

	private static Key KEY = null;
	private static final String LOGIN_USER_KEY = "LOGIN_USER_KEY";


	/**
	 * 功能描述：保存
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:41
	 */
	@Override
	public Token saveToken(LoginUser loginUser) {
		loginUser.setToken(UUID.randomUUID().toString());
		loginUser.setLoginTime(System.currentTimeMillis());
		loginUser.setExpireTime(loginUser.getLoginTime() + expireSeconds * 1000);

		TokenModel model = new TokenModel();
		model.setId(loginUser.getToken());
		model.setCreateTime(new Date());
		model.setUpdateTime(new Date());
		model.setExpireTime(new Date(loginUser.getExpireTime()));
		model.setVal(JSONObject.toJSONString(loginUser));

		tokenDao.save(model);
		// 登陆日志
		logService.save(loginUser.getId(), "登陆", true, null);

		String jwtToken = createJWTToken(loginUser);

		return new Token(jwtToken, loginUser.getLoginTime());
	}



	/**
	 * 功能描述：根据user生成jwttoken
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:39
	 */
	private String createJWTToken(LoginUser loginUser) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(LOGIN_USER_KEY, loginUser.getToken());// 放入一个随机字符串，通过该串可找到登陆用户
		//生成token
		String jwtToken = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, getKeyInstance())
				.compact();

		return jwtToken;
	}


	/**
	 * 功能描述：刷新token
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:36
	 */
	@Override
	public void refresh(LoginUser loginUser) {
		loginUser.setLoginTime(System.currentTimeMillis());
		loginUser.setExpireTime(loginUser.getLoginTime() + expireSeconds * 1000);//从新设置过期时间

		TokenModel model = tokenDao.getById(loginUser.getToken());
		model.setUpdateTime(new Date());
		model.setExpireTime(new Date(loginUser.getExpireTime()));
		model.setVal(JSONObject.toJSONString(loginUser));

		tokenDao.update(model);
	}


	/**
	 * 功能描述：通过jtwtoken 获取到user
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:36
	 */
	@Override
	public LoginUser getLoginUser(String jwtToken) {
		String uuid = getUUIDFromJWT(jwtToken);
		if (uuid != null) {
			TokenModel model = tokenDao.getById(uuid);
			return toLoginUser(model);
		}

		return null;
	}


	/**
	 * 功能描述：删除token
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:34
	 */
	@Override
	public boolean deleteToken(String jwtToken) {
		String uuid = getUUIDFromJWT(jwtToken);
		if (uuid != null) {
			TokenModel model = tokenDao.getById(uuid);
			LoginUser loginUser = toLoginUser(model);
			if (loginUser != null) {
				tokenDao.delete(uuid);
				logService.save(loginUser.getId(), "退出", true, null);

				return true;
			}
		}

		return false;
	}


	/**
	 * 功能描述：根据token获取用户
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:29
	 */
	private LoginUser toLoginUser(TokenModel model) {
		if (model == null) {
			return null;
		}
		return JSONObject.parseObject(model.getVal(), LoginUser.class);
	}


	/**
	 * 功能描述：secret生成秘钥
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:29
	 */
	private Key getKeyInstance() {
		if (KEY == null) {
			synchronized (TokenServiceJWTImpl.class) {
				if (KEY == null) {// 双重锁，不用redis可以不加
					/*加盐*/
					byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(jwtSecret);
					KEY = new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
				}
			}
		}

		return KEY;
	}


	/**
	 * 功能描述：从令牌中获取到loginuser的token的uuid
	 * 开发人员： lyx
	 * 创建时间： 2019/8/1 17:35
	 */
	private String getUUIDFromJWT(String jwt) {
		if ("null".equals(jwt) || StringUtils.isBlank(jwt)) {
			return null;
		}

		Map<String, Object> jwtClaims = null;
		try {
			jwtClaims = Jwts.parser().setSigningKey(getKeyInstance()).parseClaimsJws(jwt).getBody();
			return MapUtils.getString(jwtClaims, LOGIN_USER_KEY);
		} catch (ExpiredJwtException e) {
			log.error("{}已过期", jwt);
		} catch (Exception e) {
			log.error("{}", e);
		}

		return null;
	}

}
