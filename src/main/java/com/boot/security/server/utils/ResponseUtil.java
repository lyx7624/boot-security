package com.boot.security.server.utils;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import com.alibaba.fastjson.JSONObject;
/**
* 功能描述: resqust工具类
* 版本信息: Copyright (c)2019
* 公司信息: 智辰云科
* 开发人员: lyx
* 版本日志: 1.0
* 创建日期: 2019/8/1 17:16
*/
public class ResponseUtil {

	public static void responseJson(HttpServletResponse response, int status, Object data) {
		try {
			response.setHeader("Access-Control-Allow-Origin", "*");
			response.setHeader("Access-Control-Allow-Methods", "*");
			response.setContentType("application/json;charset=UTF-8");
			response.setStatus(status);

			response.getWriter().write(JSONObject.toJSONString(data));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
