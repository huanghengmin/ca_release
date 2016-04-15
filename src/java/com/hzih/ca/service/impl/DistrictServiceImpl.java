package com.hzih.ca.service.impl;

import cn.collin.commons.domain.PageResult;
import com.hzih.ca.dao.DistrictDao;
import com.hzih.ca.domain.District;
import com.hzih.ca.service.DistrictService;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 14-5-7
 * Time: 下午6:21
 * To change this template use File | Settings | File Templates.
 */
public class DistrictServiceImpl implements DistrictService {
    private DistrictDao districtDao;

    public DistrictDao getDistrictDao() {
        return districtDao;
    }

    public void setDistrictDao(DistrictDao districtDao) {
        this.districtDao = districtDao;
    }

    @Override
    public PageResult findProvince(int start, int limit) {
        return districtDao.findProvince(start,limit);  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public PageResult findCity(Long parentId, int start, int limit) {
        return districtDao.findCity(parentId,start,limit);  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public District findById(Long id) {
        return districtDao.findById(id);
    }
}
