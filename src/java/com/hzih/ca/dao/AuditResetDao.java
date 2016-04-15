package com.hzih.ca.dao;

import cn.collin.commons.dao.BaseDao;
import cn.collin.commons.domain.PageResult;
import com.hzih.ca.domain.AuditReset;

import java.util.Date;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-7-31
 * Time: 下午2:26
 * To change this template use File | Settings | File Templates.
 */
public interface AuditResetDao extends BaseDao {
    public PageResult pageList(int pageIndex, int limit, Date startDate, Date endDate,
                               String businessName, String businessType, String resetStatus) throws Exception;

    public void insert(List<AuditReset> auditResets) throws Exception;

    public void truncate() throws Exception;

    public void delete(String startDate, String endDate,
                       String businessName, String businessType, String resetStatus) throws Exception;

    public AuditReset findByNameTypeFileName(String businessName, String fileName, String businessType) throws Exception;
}
