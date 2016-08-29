package com.hzih.ca.entity;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-1
 * Time: 上午11:19
 * To change this template use File | Settings | File Templates.
 */
public class X509User extends X509Ca implements Serializable {


    private String idCard;
    private String phone;
    private String address;
    private String userEmail;
    private String employeeCode;
    private byte[] userCertificateAttr;
    private int row;

    public int getRow() {
        return row;
    }

    public void setRow(int row) {
        this.row = row;
    }

    /**
     * LDAP 存放用户的公钥信息
     */
    public static final String DEFAULT_userCertificateAttr   = "userCertificate;binary";


    public static String getObjAttr(){
        return "X509User";
    }
    public static String getIdCardAttr(){
        return "idCard";
    }
    public static String getPhoneAttr(){
        return "phone";
    }
    public static String getAddressAttr(){
        return "address";
    }
    public static String getUserEmailAttr(){
        return "userEmail";
    }
    public static String getEmployeeCodeAttr(){
        return "employeeCode";
    }


    public byte[] getUserCertificateAttr() {
        return userCertificateAttr;
    }

    public void setUserCertificateAttr(byte[] userCertificateAttr) {
        this.userCertificateAttr = userCertificateAttr;
    }

    public String getIdCard() {
        return idCard;
    }

    public void setIdCard(String idCard) {
        this.idCard = idCard;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getEmployeeCode() {
        return employeeCode;
    }

    public void setEmployeeCode(String employeeCode) {
        this.employeeCode = employeeCode;
    }
}
