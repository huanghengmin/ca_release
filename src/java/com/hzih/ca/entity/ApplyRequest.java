package com.hzih.ca.entity;

import com.hzih.ca.utils.Configuration;

/**
 * Created by Administrator on 15-7-24.
 */
public class ApplyRequest extends SipXml {

    private String province;
    private String city;
    private String organization;
    private String institution;
    private String place;
    private String address;

    public String getProvince() {
        return province;
    }

    public void setProvince(String province) {
        this.province = province;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getInstitution() {
        return institution;
    }

    public void setInstitution(String institution) {
        this.institution = institution;
    }

    public String getPlace() {
        return place;
    }

    public void setPlace(String place) {
        this.place = place;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String toString(){
        return "<?xml version=\"1.0\"?>\r\n\r\n" +
                "<Apply>\r\n" +
                "<DeviceType>" + deviceType + "</DeviceType>\r\n" +
                "<CmdType>" + cmdType + "</CmdType>\r\n" +
                "<DeviceID>" + deviceId + "</DeviceID>\r\n" +
                "<Province>" + province + "</Province>\r\n" +
                "<City>" + city + "</City>\r\n" +
                "<Organization>" + organization + "</Organization>\r\n" +
                "<Institution>" + institution + "</Institution>\r\n" +
                "<Place>" + place + "</Place>\r\n" +
                "<Address>" + address + "</Address>\r\n" +
                "</Apply>";

    }

    public ApplyRequest xmlToBean(byte[] buff){
        Configuration config = new Configuration(buff);
        return config.getApplyRequest();
    }
}
