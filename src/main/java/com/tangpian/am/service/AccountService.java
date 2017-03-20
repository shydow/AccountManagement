package com.tangpian.am.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.tangpian.am.dao.AccountDao;
import com.tangpian.am.model.Account;

@Service
public class AccountService {
	@Autowired
	private AccountDao accountDao;
	
	public void register(Account account) {
		accountDao.save(account);
	}
	
	public void update(Account account) {
		accountDao.save(account);
	}
	
	public Page<Account> findAll(int pageNo, int pageSize) {
		return accountDao.findAll(new PageRequest(pageNo, pageSize));
	}
	
	public void delete(String id) {
		accountDao.delete(id);
	}
}
