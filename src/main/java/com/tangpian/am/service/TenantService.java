package com.tangpian.am.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.tangpian.am.dao.TenantDao;
import com.tangpian.am.model.Tenant;

@Service
public class TenantService {
	@Autowired
	private TenantDao tenantDao;
	
	public void register(Tenant tenant) {
		tenantDao.save(tenant);
	}
	
	public void update(Tenant tenant) {
		tenantDao.save(tenant);
	}
	
	public void delete(String id) {
		tenantDao.delete(id);
	}
	
	public Page<Tenant> find(int pageNo, int pageSize) {
		return tenantDao.findAll(new PageRequest(pageNo, pageSize));
	}
}
