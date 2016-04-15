package com.hzih.ca.dao.impl;

import cn.collin.commons.dao.MyDaoSupport;
import cn.collin.commons.domain.PageResult;
import com.hzih.ca.dao.DistrictDao;
import com.hzih.ca.domain.District;

import java.util.ArrayList;
import java.util.List;


public class DistrictDaoImpl extends MyDaoSupport implements DistrictDao {

	@Override
	public void setEntityClass() {
		this.entityClass=District.class;
	}

    @Override
    public PageResult findProvince(int start, int limit) {
        int pageIndex = start/limit+1;
        String hql=" from District where mod(id,10000)=0";
        List paramsList = new ArrayList();
        String countHql = "select count(*) " + hql;
        PageResult ps = this.findByPage(hql, countHql, paramsList.toArray(),pageIndex, limit);
        return ps;
    }

    @Override
    public PageResult findCity(Long parentId, int start, int limit) {
        int pageIndex = start/limit+1;
        Long nextId=parentId+10000;
        String hql=" from District where id>="+parentId+" and id<"+nextId;
        List paramsList = new ArrayList();
        String countHql = "select count(*) " + hql;
        PageResult ps = this.findByPage(hql, countHql, paramsList.toArray(),
                pageIndex, limit);
        return ps;
    }

    @Override
    public District findById(Long id) {
        String hql=" from District where id ="+id;
        List<District> districts = getHibernateTemplate().find(hql);
        if(districts!=null){
            return districts.get(0);
        }
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }


}
