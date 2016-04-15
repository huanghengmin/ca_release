package com.hzih.ca.entity;

/**
 * Created by Administrator on 15-7-24.
 */
public class SipXml {
    public static final String True = "TRUE";
    public static final String False = "FALSE";
    public static final String ResultSuccess = "OK";
    public static final String ResultFailure = "ERROR";

    public String deviceType;
    public String cmdType;
    public String deviceId;

    public String getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public String getCmdType() {
        return cmdType;
    }

    public void setCmdType(String cmdType) {
        this.cmdType = cmdType;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }
}
