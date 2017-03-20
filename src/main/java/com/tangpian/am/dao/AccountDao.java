package com.tangpian.am.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tangpian.am.model.Account;

@Repository
public interface AccountDao extends JpaRepository<Account, String> {
	public Account findByUsername(String username);
}
