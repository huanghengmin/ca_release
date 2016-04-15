package com.hzih.ca.entity;

public class TypeDB {
	private String dbName;
	private String operation;
	private boolean oldStep;
	private boolean isTwoway;
	private String	tempTable;
	private String	maxRecords;
	private String	interval;
	private boolean enable;
	public String getDbName() {
		return dbName;
	}
	public void setDbName(String dbName) {
		this.dbName = dbName;
	}
	public String getOperation() {
		return operation;
	}
	public void setOperation(String operation) {
		this.operation = operation;
	}
	public boolean getOldStep() {
		return oldStep;
	}
	public void setOldStep(boolean oldStep) {
		this.oldStep = oldStep;
	}
	public boolean getEnable() {
		return enable;
	}
	public void setEnable(boolean enable) {
		this.enable = enable;
	}
	public String getTempTable() {
		return tempTable;
	}
	public void setTempTable(String tempTable) {
		this.tempTable = tempTable;
	}
	public String getMaxRecords() {
		return maxRecords;
	}
	public void setMaxRecords(String maxRecords) {
		this.maxRecords = maxRecords;
	}

	public String getInterval() {
		return interval;
	}
	public void setInterval(String interval) {
		this.interval = interval;
	}
	public boolean getIsTwoway() {
		return isTwoway;
	}
	public void setIsTwoway(boolean isTwoway) {
		this.isTwoway = isTwoway;
	}
	
}
