package com.hzih.ca.service;

import cn.collin.commons.domain.PageResult;
import com.hzih.ca.domain.District;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 14-5-7
 * Time: 下午6:21
 * To change this template use File | Settings | File Templates.
 */
public interface DistrictService {
    PageResult findProvince(int start,int limit);

    PageResult findCity(Long parentId,int start,int limit);

    District findById(Long id);
}
