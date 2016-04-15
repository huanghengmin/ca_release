package com.hzih.ca.entity;


import com.hzih.ca.utils.Configuration;

/**
 * Created by Administrator on 15-7-24.
 */
public class DownRequest extends SipXml {

    private String osType = SipType.Win;

    public String getOsType() {
        return osType;
    }

    public void setOsType(String osType) {
        this.osType = osType;
    }

    public String toString(){
        return "<?xml version=\"1.0\"?>\r\n\r\n" +
                "<Down>\r\n" +
                "<DeviceType>" + deviceType + "</DeviceType>\r\n" +
                "<CmdType>" + cmdType + "</CmdType>\r\n" +
                "<DeviceID>" + deviceId + "</DeviceID>\r\n" +
                "<OSType>" + osType + "</OSType>\r\n" +
                "</Down>";

    }

    public DownRequest xmlToBean(byte[] buff){
        Configuration config = new Configuration(buff);
        return config.getDownConfigRequest();
    }
}
