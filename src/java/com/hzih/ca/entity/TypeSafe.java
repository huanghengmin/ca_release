package com.hzih.ca.entity;

/**
 * Created by IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 11-10-8
 * Time: 下午6:16
 * To change this template use File | Settings | File Templates.
 */
public class TypeSafe {
    private String ipfilter;
    private boolean clientauthenable;
    private String authaddress;
    private String authport;
    private String authca;
    private String authcapass;


    public boolean getClientauthenable() {
        return clientauthenable;
    }

    public void setClientauthenable(boolean clientauthenable) {
        this.clientauthenable = clientauthenable;
    }

    public String getAuthaddress() {
        return authaddress;
    }

    public void setAuthaddress(String authaddress) {
        this.authaddress = authaddress;
    }

    public String getAuthport() {
        return authport;
    }

    public void setAuthport(String authport) {
        this.authport = authport;
    }

    public String getAuthca() {
        return authca;
    }

    public void setAuthca(String authca) {
        this.authca = authca;
    }

    public String getAuthcapass() {
        return authcapass;
    }

    public void setAuthcapass(String authcapass) {
        this.authcapass = authcapass;
    }

    public String getIpfilter() {
        return ipfilter;
    }

    public void setIpfilter(String ipfilter) {
        this.ipfilter = ipfilter;
    }
}
