package com.hzih.ca.dao;

import cn.collin.commons.dao.BaseDao;
import cn.collin.commons.domain.PageResult;
import com.hzih.ca.domain.BusinessLog;

import java.util.Date;
import java.util.List;

public interface BusinessLogDao extends BaseDao {

    /**
     * 分页查询BusinessLog
     *
     * @return
     */
    public PageResult listLogsByParams(int pageIndex, int pageLength,
                                       Date startDate, Date endDate, String logLevel, String businessName)  throws Exception;

    public void truncate()  throws Exception;


    public void delete(String startDate, String endDate, String logLevel, String businessName) throws Exception;

    public PageResult listCompareLogsByParams(int pageIndex, int limit, Date startDate, Date endDate,
                                              String businessType, String businessName) throws Exception;

    public int getCount(String businessName, String businessType, String fileName, String plugin) throws Exception;

    public List<BusinessLog> findByNameTypeFileName(String businessName, String businessType, String fileName) throws Exception;

    public List<BusinessLog> listCompareLogsByNameAndType(String businessName, String file) throws Exception;
}
