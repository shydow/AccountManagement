package com.tangpian.am.service;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;

public class AppService {
	@Autowired
	private StringRedisTemplate redisTemplate;
	
	public void createToken(String username, String password) {
		String token = UUID.randomUUID().toString();
		redisTemplate.opsForValue().set(username, token);
	}

	public boolean validateToken(String token) {
		// TODO
		return false;
	}
}
