package com.hzih.ca.entity;

public class TypeTable {
	private boolean insert;
	private boolean update;
	private boolean delete;
	private String tableName;
	private String seqnumber;
	private String interval;
	private boolean deleteEnable;
	private boolean onlyInsert;
	private String condition ;
	private String sourceTableName;
	private String targetDBName;
	
	public String getTargetDBName() {
		return targetDBName;
	}
	public void setTargetDBName(String targetDBName) {
		this.targetDBName = targetDBName;
	}
	public boolean getInsert() {
		return insert;
	}
	public void setInsert(boolean insert) {
		this.insert = insert;
	}
	public boolean getUpdate() {
		return update;
	}
	public void setUpdate(boolean update) {
		this.update = update;
	}
	public boolean getDelete() {
		return delete;
	}
	public void setDelete(boolean delete) {
		this.delete = delete;
	}
	public String getTableName() {
		return tableName;
	}
	public void setTableName(String tableName) {
		this.tableName = tableName;
	}
	public String getSeqnumber() {
		return seqnumber;
	}
	public void setSeqnumber(String seqnumber) {
		this.seqnumber = seqnumber;
	}
	public String getInterval() {
		return interval;
	}
	public void setInterval(String interval) {
		this.interval = interval;
	}
	public boolean getDeleteEnable() {
		return deleteEnable;
	}
	public void setDeleteEnable(boolean deleteEnable) {
		this.deleteEnable = deleteEnable;
	}
	public boolean getOnlyInsert() {
		return onlyInsert;
	}
	public void setOnlyInsert(boolean onlyInsert) {
		this.onlyInsert = onlyInsert;
	}
	public String getCondition() {
		return condition;
	}
	public void setCondition(String condition) {
		this.condition = condition;
	}
	public String getSourceTableName() {
		return sourceTableName;
	}
	public void setSourceTableName(String sourceTableName) {
		this.sourceTableName = sourceTableName;
	}
}
