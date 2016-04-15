package com.hzih.ca.dao;

import cn.collin.commons.dao.BaseDao;
import com.hzih.ca.domain.Role;

public interface RoleDao extends BaseDao {

    public Role findByName(String name) throws Exception;
}
