package com.hzih.ca.web.action.ldap;

import com.hzih.ca.utils.X509Context;
import com.inetec.common.util.OSInfo;
import com.inetec.common.util.Proc;
import org.apache.log4j.Logger;

import java.io.File;

/**
 * Created by Administrator on 14-7-21.
 */
public class LdapBakUtils {
    private Logger logger = Logger.getLogger(LdapBakUtils.class);

    public boolean ldapBak() throws Exception {
        Proc proc = new Proc();
        String command = null;
        if (OSInfo.getOSInfo().isWin()) {
            command = " slapcat -v -l " + X509Context.ldap_bak_ldif;
        } else {
            command = " slapcat -v -l " + X509Context.ldap_bak_ldif;
        }
        proc.exec(command);
        File file = new File(X509Context.ldap_bak_ldif);
        if (file.exists() && file.length() > 0) {
            return true;
        } else {
            return false;
        }
    }




    public boolean ldapStatus()throws Exception{
        try {
            Proc proc= new Proc();
            proc.exec("service slapd status");
            String msg_on = proc.getOutput();
            if(msg_on.contains("is running")) {
                return true;
            }else {
                return false;
            }
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
            return false;
        }
    }


    public boolean ldapStop()throws Exception{
        try {
            Proc proc= new Proc();
            proc.exec("service slapd stop");
            Thread.sleep(2*1000);
            if(ldapStatus()){
                return true;
            }else {
                return false;
            }
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
            return false;
        }
    }

    public boolean ldapStart()throws Exception{
        try {
            Proc proc= new Proc();
            proc.exec("service slapd start");
            Thread.sleep(2*1000);
            if(ldapStatus()){
                return true;
            }else {
                return false;
            }
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
            return false;
        }
    }




    public boolean ldapRestore() throws Exception {
        boolean flag = false;
        if(ldapStatus()){
             if(ldapStop()){
                 Proc proc = new Proc();
                 String command = null;
                 if (OSInfo.getOSInfo().isWin()) {
                     command = " slapadd -v -l " + X509Context.ldap_bak_ldif;
                 } else {
                     command = " slapadd -v -l " + X509Context.ldap_bak_ldif;
                 }
                 proc.exec(command);
                 if (proc.getResultCode() != -1) {
                     flag = true;
                 }
             }
        }else {
            Proc proc = new Proc();
            String command = null;
            if (OSInfo.getOSInfo().isWin()) {
                command = " slapadd -v -l " + X509Context.ldap_bak_ldif;
            } else {
                command = " slapadd -v -l " + X509Context.ldap_bak_ldif;
            }
            proc.exec(command);
            if (proc.getResultCode() != -1) {
                flag = true;
            }
        }
        return flag;
    }

}
