package com.hzih.ca.entity;
/**
 * 
 * @author 钱晓盼
 *
 */

public class TypeData {
	private String serverAddress;
	private String port;
	private String poolMin;
	private String poolMax;
	private String type;
	private String tryTime;
	private String charset;
	private String name;
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
	public String getPoolMin() {
		return poolMin;
	}
	public void setPoolMin(String poolMin) {
		this.poolMin = poolMin;
	}
	public String getPoolMax() {
		return poolMax;
	}
	public void setPoolMax(String poolMax) {
		this.poolMax = poolMax;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getTryTime() {
		return tryTime;
	}
	public void setTryTime(String tryTime) {
		this.tryTime = tryTime;
	}
	public String getCharset() {
		return charset;
	}
	public void setCharset(String charset) {
		this.charset = charset;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
}
