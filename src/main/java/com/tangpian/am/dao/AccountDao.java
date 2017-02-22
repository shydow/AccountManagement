package com.tangpian.am.dao;

import org.apache.ibatis.annotations.Mapper;

import com.tangpian.am.model.Account;

@Mapper
public interface AccountDao {
	
	public Account read(String id);
	
	public void create(Account account);
	
	public void update(Account account);
	
	public void delete(String id);
	
}
