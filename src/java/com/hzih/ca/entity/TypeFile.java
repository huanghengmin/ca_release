package com.hzih.ca.entity;

public class TypeFile {
	private String userName;
	private String password;
	private String serverAddress;
	private String port;
	private String charset;
	private String dir;
	private String filterTypes;
	private String notFilterTypes;
	private Integer interval;
	private Boolean isIncludeSubDir;
	private Boolean deleteFile;
	private String protocol;
	private Boolean isTwoWay;
	private Boolean isOnlyAdd;
	private Integer threads;
	private Integer fileListSize;
	private Integer packetSize;
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getServerAddress() {
		return serverAddress;
	}
	public void setServerAddress(String serverAddress) {
		this.serverAddress = serverAddress;
	}
	public String getPort() {
		return port;
	}
	public void setPort(String port) {
		this.port = port;
	}
	public String getCharset() {
		return charset;
	}
	public void setCharset(String charset) {
		this.charset = charset;
	}
	public String getDir() {
		return dir;
	}
	public void setDir(String dir) {
		this.dir = dir;
	}
	public String getFilterTypes() {
		return filterTypes;
	}
	public void setFilterTypes(String filterTypes) {
		this.filterTypes = filterTypes;
	}
	public String getNotFilterTypes() {
		return notFilterTypes;
	}
	public void setNotFilterTypes(String notFilterTypes) {
		this.notFilterTypes = notFilterTypes;
	}
	public Integer getInterval() {
		return interval;
	}
	public void setInterval(Integer interval) {
		this.interval = interval;
	}
	public Boolean getIsIncludeSubDir() {
		return isIncludeSubDir;
	}
	public void setIsIncludeSubDir(Boolean isIncludeSubDir) {
		this.isIncludeSubDir = isIncludeSubDir;
	}
	public Boolean getDeleteFile() {
		return deleteFile;
	}
	public void setDeleteFile(Boolean deleteFile) {
		this.deleteFile = deleteFile;
	}
	public String getProtocol() {
		return protocol;
	}
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	public Boolean getIsTwoWay() {
		return isTwoWay;
	}
	public void setIsTwoWay(Boolean isTwoWay) {
		this.isTwoWay = isTwoWay;
	}
	public Boolean getIsOnlyAdd() {
		return isOnlyAdd;
	}
	public void setIsOnlyAdd(Boolean isOnlyAdd) {
		this.isOnlyAdd = isOnlyAdd;
	}
	public Integer getThreads() {
		return threads;
	}
	public void setThreads(Integer threads) {
		this.threads = threads;
	}
	public Integer getFileListSize() {
		return fileListSize;
	}
	public void setFileListSize(Integer fileListSize) {
		this.fileListSize = fileListSize;
	}
	public Integer getPacketSize() {
		return packetSize;
	}
	public void setPacketSize(Integer packetSize) {
		this.packetSize = packetSize;
	}
	
	
}
