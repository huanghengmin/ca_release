package com.hzih.ca.dao.impl;

import cn.collin.commons.dao.MyDaoSupport;
import cn.collin.commons.domain.PageResult;
import com.hzih.ca.dao.SysLogDao;
import com.hzih.ca.domain.SysLog;
import com.hzih.ca.utils.StringUtils;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SysLogDaoImpl extends MyDaoSupport implements SysLogDao {
	private final static Logger logger = Logger.getLogger(SysLogDaoImpl.class);

	@Override
	public void setEntityClass() {
		this.entityClass = SysLog.class;
	}

	/**
	 * 分页查询SysLog
	 * 
	 */
	public PageResult listLogsByParams(int pageIndex, int pageLength,
			Date startDate, Date endDate, String logLevel) {
		StringBuffer sb = new StringBuffer(" from SysLog s where 1=1");
		List params = new ArrayList(3);// 手动指定容量，避免多次扩容
		if(startDate!=null){
			sb.append(" and date_format(logTime,'%Y-%m-%d')>= date_format(?,'%Y-%m-%d')");
			params.add(startDate);
		}
		if(endDate!=null){
			sb.append(" and date_format(logTime,'%Y-%m-%d')<= date_format(?,'%Y-%m-%d')");
			params.add(endDate);
		}

		if (StringUtils.isNotBlank(logLevel)) {
			sb.append(" and level = ?");
			params.add(logLevel);
		}
		String countString = "select count(*) " + sb.toString();
		
		String queryString = sb.toString();

		PageResult ps = this.findByPage(queryString, countString, params
				.toArray(), pageIndex, pageLength);
		logger.debug(ps == null ? "ps=null" : "ps.results.size:"
				+ ps.getResults().size());
		return ps;
	}

}
