package com.hzih.ca.dao.impl;

import cn.collin.commons.dao.MyDaoSupport;
import com.hzih.ca.dao.PermissionDao;
import com.hzih.ca.domain.Permission;

public class PermissionDaoImpl extends MyDaoSupport implements PermissionDao {

	@Override
	public void setEntityClass() {
		this.entityClass = Permission.class;
	}

}
