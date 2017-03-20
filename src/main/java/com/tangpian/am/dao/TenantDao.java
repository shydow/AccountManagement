package com.tangpian.am.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tangpian.am.model.Tenant;

@Repository
public interface TenantDao extends JpaRepository<Tenant, String> {

}
