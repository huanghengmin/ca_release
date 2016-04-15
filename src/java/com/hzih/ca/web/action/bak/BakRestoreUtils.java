package com.hzih.ca.web.action.bak;

import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ldap.LdapBakUtils;
import com.hzih.ca.web.action.mysql.MysqlBakUtils;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Administrator on 14-7-21.
 */
public class BakRestoreUtils {
    private static Logger logger = Logger.getLogger(BakRestoreUtils.class);

    public static boolean bak(String path){
        boolean fg = false;
        try {
            fg = MysqlBakUtils.backup();
        } catch (IOException e) {
             logger.info(e.getMessage(),e);
            return false;
        }
        if(fg) {
            LdapBakUtils ldapBakUtils = new LdapBakUtils();
            boolean flag = false;
            try {
                flag = ldapBakUtils.ldapBak();
            } catch (Exception e) {
                logger.info(e.getMessage(),e);
                return false;
            }
            if (flag) {
                if (path.endsWith(File.separator)) {
                    TarUtils tarUtils = new TarUtils();
                    //单个文件打包
//                    tarUtils.execute(path + path, path + X509Context.bak_file + ".tar", path + X509Context.bak_file);
                    List<String> array = new ArrayList<>();
                    array.add(X509Context.config_path);
                    array.add(X509Context.license_path);
                    array.add(X509Context.security_path);
                    array.add(X509Context.store_path);
                    array.add(X509Context.ldap_bak_ldif);
                    array.add(X509Context.mysql_bak_sql);
                    tarUtils.execute(array,path + X509Context.bak_file + ".tar", path + X509Context.bak_file);
                } else {
                    path += File.separator;
                    TarUtils tarUtils = new TarUtils();
                    //单个文件打包
//                    tarUtils.execute(path, path + X509Context.bak_file + ".tar", path + X509Context.bak_file);
                    List<String> array = new ArrayList<>();
                    array.add(X509Context.config_path);
                    array.add(X509Context.license_path);
                    array.add(X509Context.security_path);
                    array.add(X509Context.store_path);
                    array.add(X509Context.ldap_bak_ldif);
                    array.add(X509Context.mysql_bak_sql);
                    //多个文件打包
                    tarUtils.execute(array,path + X509Context.bak_file + ".tar", path + X509Context.bak_file);
                }
                File f = new File(path + X509Context.bak_file);
                if (f.exists() && f.length() > 0) {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }else {
            return false;
        }
    }

    public static boolean bakRestore(String path){
        if(path.endsWith(File.separator)){
            GZip.unTargzFile(path+ X509Context.bak_file,path);
            try {
                MysqlBakUtils.recover();
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
                return false;
            }
            LdapBakUtils ldapBakUtils = new LdapBakUtils();
            try {
                ldapBakUtils.ldapRestore();
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                return false;
            }
            try {
                ldapBakUtils.ldapStart();
            } catch (Exception e) {
                logger.error(e.getMessage(),e);
                return false;
            }
            return true;
        }else {
            path += File.separator;
            GZip.unTargzFile(path+ X509Context.bak_file,path);
            try {
                MysqlBakUtils.recover();
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
                return false;
            }
            LdapBakUtils ldapBakUtils = new LdapBakUtils();
            try {
                ldapBakUtils.ldapRestore();
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                return false;
            }
            try {
                ldapBakUtils.ldapStart();
            } catch (Exception e) {
                logger.error(e.getMessage(),e);
                return false;
            }
            return true;
        }
    }
}
