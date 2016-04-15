package com.hzih.ca.dao.impl;

import cn.collin.commons.dao.MyDaoSupport;
import cn.collin.commons.domain.PageResult;
import com.hzih.ca.dao.BusinessLogDao;
import com.hzih.ca.domain.BusinessLog;
import com.hzih.ca.utils.StringUtils;
import com.inetec.common.config.nodes.Type;
import org.hibernate.Query;
import org.hibernate.SQLQuery;
import org.hibernate.Session;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BusinessLogDaoImpl extends MyDaoSupport implements BusinessLogDao {

    @Override
    public void setEntityClass() {
        this.entityClass = BusinessLog.class;
    }

    /**
     * 分页查询BusinessLog
     *
     * @return
     */
    public PageResult listLogsByParams(int pageIndex, int pageLength,
                                       Date startDate, Date endDate, String businessType, String businessName) {
        StringBuffer sb = new StringBuffer(" from BusinessLog s where 1=1");
        List params = new ArrayList(4);// 手动指定容量，避免多次扩容
        if(startDate!=null){
            sb.append(" and date_format(logTime,'%Y-%m-%d')>= date_format(?,'%Y-%m-%d')");
            params.add(startDate);
        }
        if(endDate!=null){
            sb.append(" and date_format(logTime,'%Y-%m-%d')<= date_format(?,'%Y-%m-%d')");
            params.add(endDate);
        }

        if (StringUtils.isNotBlank(businessType)) {
            sb.append(" and businessType = ?");
            params.add(businessType);
        }
        if (StringUtils.isNotBlank(businessName)) {
            sb.append(" and businessName like ?");
            params.add("%"+businessName+"%");
        }
        sb.append(" order by id desc");
        String countString = "select count(*) " + sb.toString();
        String queryString = sb.toString();

        PageResult ps = this.findByPage(queryString, countString, params
                .toArray(), pageIndex, pageLength);
        logger.debug(ps == null ? "ps=null" : "ps.results.size:"
                + ps.getResults().size());
        return ps;
    }

    @Override
    public void truncate() throws Exception {
        String sql = "truncate business_log";
        Session session = getSession();
        SQLQuery sqlQuery = session.createSQLQuery(sql);
        sqlQuery.addEntity(BusinessLog.class);
        sqlQuery.executeUpdate();
    }

    @Override
    public void delete(String startDate, String endDate, String businessType, String businessName) throws Exception {
        String sql = "delete from business_log where" ;
        if(StringUtils.isNotBlank(startDate)){
            sql += " 1=1 and date_format(log_time,'%Y-%m-%d')>= '"+startDate+"'";
        }
        if(StringUtils.isNotBlank(endDate)){
            sql += " 1=1 and date_format(log_time,'%Y-%m-%d')<= '"+endDate+"'";
        }

        if (StringUtils.isNotBlank(businessType)) {
            sql += " 1=1 and business_type = '"+businessType+"'";
        }
        if (StringUtils.isNotBlank(businessName)) {
            sql += " 1=1 and business_name like '"+businessName+"'";
        }
        Session session = getSession();
        SQLQuery sqlQuery = session.createSQLQuery(sql);
        sqlQuery.addEntity(BusinessLog.class);
        sqlQuery.executeUpdate();
    }

    @Override
    public PageResult listCompareLogsByParams(int pageIndex, int limit, Date startDate, Date endDate,
                                              String businessType, String businessName) throws Exception {
        StringBuffer sb = new StringBuffer(" from BusinessLog s where 1=1");
        String hql = new String("from BusinessLog s where flag = 0");
        Session session = getSession();
        Query query = session.createQuery(hql);
        List list = query.list();
        if(list.size()>0){
            List params = new ArrayList(5);// 手动指定容量，避免多次扩容
            if(startDate!=null){
                sb.append(" and date_format(logTime,'%Y-%m-%d')>= date_format(?,'%Y-%m-%d')");
                params.add(startDate);
            }
            if(endDate!=null){
                sb.append(" and date_format(logTime,'%Y-%m-%d')<= date_format(?,'%Y-%m-%d')");
                params.add(endDate);
            }

            if (StringUtils.isNotBlank(businessType)) {
                sb.append(" and businessType = ?");
                params.add(businessType);
            }
            if (StringUtils.isBlank(businessType)) {
                sb.append(" and businessType = ?");
                params.add(Type.s_app_file);
            }
            if (StringUtils.isNotBlank(businessName)) {
                sb.append(" and businessName like ?");
                params.add("%"+businessName+"%");
            }
            sb.append(" and flag = 0 group by fileName");
            String countString = "select count(*) " + sb.toString();
            String queryString = sb.toString();

            PageResult ps = this.findByPage(queryString, countString, params
                    .toArray(), pageIndex, limit);
            logger.debug(ps == null ? "ps=null" : "ps.results.size:"
                    + ps.getResults().size());
            return ps;
        }
        return null;
    }


    public int getCount(String businessName, String businessType, String fileName, String plugin) throws Exception {

        String sql = "select sum(audit_count) from business_log " +
                "where business_type = '"+businessType+"' and file_name = '"+fileName+"' and business_name = '"+businessName+"' and plugin = '"+plugin+"' and flag = 0;";
        Session session = getSession();
        SQLQuery sqlQuery = session.createSQLQuery(sql);
        List list = sqlQuery.list();
        Object obj = list.get(0);
        int sum = 0;
        if(obj!=null){
            sum = Integer.parseInt(obj.toString());
        }
        return sum;
    }

    @Override
    public List<BusinessLog> findByNameTypeFileName(String businessName, String businessType, String fileName) throws Exception {
        String sql = "select * from business_log " +
                "where business_type = '"+businessType+"' and file_name = '"+fileName+"' and business_name = '"+businessName+"' and flag = 0;";
        Session session = getSession();
        Query sqlQuery = session.createSQLQuery(sql).addEntity(BusinessLog.class);
        List list = sqlQuery.list();
        return list;
    }

    @Override
    public List<BusinessLog> listCompareLogsByNameAndType(String businessName, String file) throws Exception {
        String sql = "select * from business_log " +
                "where business_type = 'file' and business_name = '"+businessName+"' and flag = 0;";
        Session session = getSession();
        Query sqlQuery = session.createSQLQuery(sql).addEntity(BusinessLog.class);
        List list = sqlQuery.list();
        return list;
    }

}
