package com.hzih.ca.domain;

import java.util.Date;

/**
 * 系统日志审计表
 * 
 * @author collin.code@gmail.com
 * @hibernate.class table="sys_log"
 */
public class SysLog {
	/**
	 * @hibernate.id column="Id" generator-class="identity"
	 *               type="java.lang.Long"
	 */
	Long id;

	/**
	 * 产生时间
	 * 
	 * @hibernate.property column="log_time" type="java.util.Date"
	 */
	Date logTime;

	/**
	 * 日志等级
	 * 
	 * @hibernate.property column="level" type="java.lang.String"
	 */
	String level;

	/**
	 * 审计模块
	 * 
	 * @hibernate.property column="audit_module" type="java.lang.String"
	 */
	String auditModule;

	/**
	 * 审计行为
	 * 
	 * @hibernate.property column="audit_action" type="java.lang.String"
	 */
	String auditAction;

	/**
	 * 审计内容
	 * 
	 * @hibernate.property column="audit_info" type="java.lang.String"
	 */
	String auditInfo;

	public SysLog() {
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Date getLogTime() {
		return logTime;
	}

	public void setLogTime(Date logTime) {
		this.logTime = logTime;
	}

	public String getLevel() {
		return level;
	}

	public void setLevel(String level) {
		this.level = level;
	}

	public String getAuditModule() {
		return auditModule;
	}

	public void setAuditModule(String auditModule) {
		this.auditModule = auditModule;
	}

	public String getAuditAction() {
		return auditAction;
	}

	public void setAuditAction(String auditAction) {
		this.auditAction = auditAction;
	}

	public String getAuditInfo() {
		return auditInfo;
	}

	public void setAuditInfo(String auditInfo) {
		this.auditInfo = auditInfo;
	}
}
