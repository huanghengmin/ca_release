package com.hzih.ca.entity;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-1
 * Time: 上午11:19
 * To change this template use File | Settings | File Templates.
 */
public class X509Server extends X509Ca implements Serializable {

    private String  serverIp;
    /**
     * LDAP 存放服务器证书的公钥信息
     */
    private byte[] userCertificateAttr;

    public byte[] getUserCertificateAttr() {
        return userCertificateAttr;
    }

    public void setUserCertificateAttr(byte[] userCertificateAttr) {
        this.userCertificateAttr = userCertificateAttr;
    }

    public static final String DEFAULT_userCertificateAttr   = "userCertificate;binary";

    public String getServerIp() {
        return serverIp;
    }

    public void setServerIp(String serverIp) {
        this.serverIp = serverIp;
    }


    public static String getObjAttr() {
        return "X509Server";
    }

    public static String getServerIpAttr() {
        return "serverIp";
    }


}
