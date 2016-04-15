package com.hzih.ca.entity;

/**
 * Created by Administrator on 15-7-24.
 */
public class ApplyResponse extends SipXml {
    private String result;

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String toString(){
        return "<?xml version=\"1.0\"?>\r\n\r\n" +
                "<Response>\r\n" +
                "<DeviceType>" + deviceType + "</DeviceType>\r\n" +
                "<CmdType>" + cmdType + "</CmdType>\r\n" +
                "<DeviceID>" + deviceId + "</DeviceID>\r\n" +
                "<Result>" + result + "</Result>\r\n" +
                "</Response>";

    }
}
