package com.hzih.ca.dao.impl;

import cn.collin.commons.dao.MyDaoSupport;
import cn.collin.commons.domain.PageResult;
import com.hzih.ca.dao.AuditResetDao;
import com.hzih.ca.domain.AuditReset;
import com.hzih.ca.utils.StringUtils;
import org.hibernate.Query;
import org.hibernate.SQLQuery;
import org.hibernate.Session;
import org.hibernate.Transaction;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-7-31
 * Time: 下午2:27
 * To change this template use File | Settings | File Templates.
 */
public class AuditResetDaoImpl extends MyDaoSupport implements AuditResetDao{
    @Override
    public void setEntityClass() {
        this.entityClass = AuditReset.class;
    }

    @Override
    public PageResult pageList(int pageIndex,int limit, Date startDate, Date endDate,
                               String businessName, String businessType, String resetStatus) throws Exception {
        StringBuffer sb = new StringBuffer("from AuditReset where 1=1 ") ;
        List params = new ArrayList(5);
        if(startDate!=null){
			sb.append(" and date_format(importTime,'%Y-%m-%d')>= date_format(?,'%Y-%m-%d')");
			params.add(startDate);
		}
		if(endDate!=null){
			sb.append(" and date_format(importTime,'%Y-%m-%d')<= date_format(?,'%Y-%m-%d')");
			params.add(endDate);
		}
        if(StringUtils.isNotBlank(businessName)){
            sb.append(" and businessName like ?");
            params.add("%" + businessName + "%");
        }
        if(StringUtils.isNotBlank(businessType)){
            sb.append(" and businessType = ?");
            params.add(businessType);
        }
        if(StringUtils.isNotBlank(resetStatus)&& !resetStatus.equalsIgnoreCase("全部")){
            sb.append(" and resetStatus = ?");
            params.add(Integer.valueOf(resetStatus));
        }
        sb.append(" order by id desc ");
        String countString = "select count(*) " + sb.toString();
		String queryString = sb.toString();
		PageResult ps = this.findByPage(queryString, countString, params.toArray(), pageIndex, limit);
        return ps;
    }

    @Override
    public void insert(List<AuditReset> list) throws Exception {
        Session session = getSession();
        Transaction tx = session.beginTransaction(); //使用Hibernate事务处理边界
        for(int i=0;i<list.size();i++) {
            AuditReset auditReset = list.get(i);
            auditReset.setResetCount(1);
            auditReset.setImportTime(new Date());
            session.save(auditReset);
            // 以每50个数据作为一个处理单元
            if(i%50==0) {
            // 只是将Hibernate缓存中的数据提交到数据库，保持与数据库数据的同步
                session.flush();
            // 清除内部缓存的全部数据，及时释放出占用的内存
                session.clear();
            }
        }
        tx.commit();
    }

    @Override
    public void truncate() throws Exception {
        String sql = "truncate audit_reset";
        Session session = getSession();
        SQLQuery sqlQuery = session.createSQLQuery(sql);
        sqlQuery.executeUpdate();
    }

    @Override
    public void delete(String startDate, String endDate, String businessName, String businessType, String resetStatus) throws Exception {
        String sql = "delete from audit_reset where 1=1" ;
        if(StringUtils.isNotBlank(startDate)){
            sql += " and date_format(import_time,'%Y-%m-%d')>= 'date_format("+startDate+"','%Y-%m-%d')";
        }
        if(StringUtils.isNotBlank(endDate)){
            sql += " and date_format(import_time,'%Y-%m-%d')<= 'date_format("+endDate+"','%Y-%m-%d')";
        }

        if (StringUtils.isNotBlank(businessType)) {
            sql += " and business_type = '"+businessType+"'";
        }
        if (StringUtils.isNotBlank(businessName)) {
            sql += " and business_name like '%"+businessName+"%'";
        }
        if(StringUtils.isNotBlank(resetStatus)&& !resetStatus.equalsIgnoreCase("全部")){
            sql += " and reset_status = " + Integer.valueOf(resetStatus);
        }
        if(resetStatus.equals("全部")) {
            sql = "delete from audit_reset where reset_status in (0,1);";
        }
        Session session = getSession();
        SQLQuery sqlQuery = session.createSQLQuery(sql);
        sqlQuery.executeUpdate();
    }

    @Override
    public AuditReset findByNameTypeFileName(String businessName, String fileName, String businessType) throws Exception {
        StringBuffer sb = new StringBuffer("select * from audit_reset where 1=1 ") ;
        if(StringUtils.isNotBlank(businessName)){
            sb.append(" and business_name = '"+businessName+"'");
        }
        if(StringUtils.isNotBlank(businessType)){
            sb.append(" and business_type = '"+businessType+"'");
        }
        if(StringUtils.isNotBlank(fileName)){
            sb.append(" and file_name = '"+fileName+"'");
        }

        Session session = getSession();
        Query query = session.createSQLQuery(sb.toString()+";").addEntity(AuditReset.class);
        List<AuditReset> list = query.list();
        if(list.size()>0){
            return list.get(0);
        } else {
            return null;
        }
    }
}
