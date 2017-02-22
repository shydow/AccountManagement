package com.tangpian.am.service;

import org.springframework.beans.factory.annotation.Autowired;

import com.tangpian.am.dao.AccountDao;
import com.tangpian.am.model.Account;

public class AccountService {

	@Autowired
	private AccountDao accountDao;
	
	public void create(Account account) {
		accountDao.create(account);
	}
	
}
