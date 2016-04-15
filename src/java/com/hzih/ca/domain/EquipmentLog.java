package com.hzih.ca.domain;

import java.util.Date;

/**
 * 设备日志
 * 
 * @author collin.code@gmail.com
 * @hibernate.class table="equipment_log"
 */
public class EquipmentLog {
	/**
	 * @hibernate.id column="Id" generator-class="identity"
	 *               type="java.lang.Long"
	 */
	Long id;

	/**
	 * 日志时间
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
	 * 链路名
	 * 
	 * @hibernate.property column="link_name" type="java.lang.String"
	 */
	String linkName;

	/**
	 * 设备名
	 * 
	 * @hibernate.property column="equipment_name" type="java.lang.String"
	 */
	String equipmentName;

	/**
	 * 日志内容
	 * 
	 * @hibernate.property column="log_info" type="java.lang.String"
	 */
	String logInfo;

	public EquipmentLog() {

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

	public String getLinkName() {
		return linkName;
	}

	public void setLinkName(String linkName) {
		this.linkName = linkName;
	}

	public String getEquipmentName() {
		return equipmentName;
	}

	public void setEquipmentName(String equipmentName) {
		this.equipmentName = equipmentName;
	}

	public String getLogInfo() {
		return logInfo;
	}

	public void setLogInfo(String logInfo) {
		this.logInfo = logInfo;
	}
}
