package com.tangpian.am.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tangpian.am.model.Role;

@Repository
public interface RoleDao extends JpaRepository<Role, String>{

}
