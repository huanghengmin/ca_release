package com.hzih.ca.web.utils;

import com.hzih.ca.entity.X509Server;
import com.hzih.ca.utils.X509Context;

import java.io.*;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-3
 * Time: 下午2:44
 * To change this template use File | Settings | File Templates.
 */
public class X509ServerConfigUtils {

    public static String applyServer(X509Server x509Server) {
        StringBuilder config = new StringBuilder();
        config.append("[ req ]").append("\n");
        config.append("default_keyfile         = " + x509Server.getCn() + X509Context.keyName).append("\n");
        config.append("prompt                  = no").append("\n");
        config.append("string_mask             = utf8only").append("\n");
        config.append("distinguished_name      = req_distinguished_name").append("\n");

        config.append("[ req_distinguished_name ]").append("\n");
        config.append("C                       = " + X509Context.default_country_code).append("\n");
//        config.append("ST                      = " + x509Server.getProvince()).append("\n");
        config.append("stateOrProvinceName     = " + x509Server.getProvince()).append("\n");
//        config.append("L                       = " + x509Server.getCity()).append("\n");
        config.append("localityName            = " + x509Server.getCity()).append("\n");
        config.append("O                       = " + x509Server.getOrganization()).append("\n");
        config.append("OU                      = " + x509Server.getInstitution()).append("\n");
//        config.append("organizationalUnitName  = " + x509Server.getInstitution()).append("\n");
        config.append("CN                      = " + x509Server.getCn()).append("\n");
        return config.toString();
    }


    public static boolean buildServer(X509Server x509Server,String storeDirectory) {
        String text = applyServer(x509Server);
        File file = new File(storeDirectory + "/" + x509Server.getCn() + X509Context.config_type_certificate);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
        OutputStreamWriter osw  = null;
        try {
            osw = new OutputStreamWriter(fos, X509Context.charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return false;
        }
        try {
            osw.write(text);
            osw.flush();
            osw.close();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        if (!file.exists()) {
            return false;
        }
        return true;
    }

}
