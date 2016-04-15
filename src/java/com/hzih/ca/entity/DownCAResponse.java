package com.hzih.ca.entity;

/**
 * Created by Administrator on 15-7-24.
 */
public class DownCAResponse extends SipXml {

    private String result;
    private String keyFileName;
    private long keyFileSize;
    private String keyFile;
    private String crtFileName;
    private long crtFileSize;
    private String crtFile;



    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getKeyFileName() {
        return keyFileName;
    }

    public void setKeyFileName(String keyFileName) {
        this.keyFileName = keyFileName;
    }

    public long getKeyFileSize() {
        return keyFileSize;
    }

    public void setKeyFileSize(long keyFileSize) {
        this.keyFileSize = keyFileSize;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public String getCrtFileName() {
        return crtFileName;
    }

    public void setCrtFileName(String crtFileName) {
        this.crtFileName = crtFileName;
    }

    public long getCrtFileSize() {
        return crtFileSize;
    }

    public void setCrtFileSize(long crtFileSize) {
        this.crtFileSize = crtFileSize;
    }

    public String getCrtFile() {
        return crtFile;
    }

    public void setCrtFile(String crtFile) {
        this.crtFile = crtFile;
    }

    public String toString(){
        return "<?xml version=\"1.0\"?>\r\n\r\n" +
                "<Response>\r\n" +
                "<DeviceType>" + deviceType + "</DeviceType>\r\n" +
                "<DeviceID>" + deviceId + "</DeviceID>\r\n" +
                "<CmdType>" + SipType.DownCA + "</CmdType>\r\n" +
                "<KeyFileName>" + keyFileName + "</KeyFileName>\r\n" +
                "<KeyFileSize>" + keyFileSize + "</KeyFileSize>\r\n" +
                "<KeyFile>" + keyFile + "</KeyFile>\r\n" +
                "<CrtFileName>" + crtFileName + "</CrtFileName>\r\n" +
                "<CrtFileSize>" + crtFileSize + "</CrtFileSize>\r\n" +
                "<CrtFile>" + crtFile + "</CrtFile>\r\n" +
                "<Result>" + result + "</Result>\r\n" +
                "</Response>";

    }
}
