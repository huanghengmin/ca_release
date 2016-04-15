package com.hzih.ca.web.utils;

import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;

import java.io.*;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 13-7-2
 * Time: 下午12:31
 * To change this template use File | Settings | File Templates.
 */
public class X509CAConfigUtils {
    /**
     * CA请求文件信息
     * @param x509Ca
     * @return
     */
    public static String applyCA(X509Ca x509Ca) {
        StringBuilder config = new StringBuilder();
        config.append("[ req ]").append("\n");
        config.append("default_keyfile     = " + x509Ca.getCn() + X509Context.keyName).append("\n");
        config.append("prompt              = no").append("\n");
        config.append("string_mask         = utf8only").append("\n");
        config.append("distinguished_name  = req_distinguished_name").append("\n");
        config.append("x509_extensions     = "+ X509Context.certificate_type_ca).append("\n");

        config.append("[ req_distinguished_name ]").append("\n");
        config.append("C                   = " + X509Context.default_country_code).append("\n");
        config.append("stateOrProvinceName = " + x509Ca.getProvince()).append("\n");
        config.append("localityName        = " + x509Ca.getCity()).append("\n");
//        config.append("ST    = " + x509Ca.getProvince()).append("\n");
//        config.append("L           = " + x509Ca.getCity()).append("\n");
        config.append("CN                  = " + x509Ca.getCn()).append("\n");

        config.append("[ "+ X509Context.certificate_type_ca +"  ]").append("\n");
        config.append("basicConstraints              = CA:true").append("\n");
        config.append("subjectKeyIdentifier          = hash").append("\n");
        config.append("authorityKeyIdentifier        = keyid:always, issuer:always").append("\n");
        config.append("keyUsage                      = nonRepudiation, keyCertSign,cRLSign").append("\n");
        config.append("crlDistributionPoints         = "+ X509Context.crl_dps).append("\n");

        config.append("["+ X509Context.crl_dps +"]").append("\n");
        config.append("fullname               = URI:http://" + LdapXMLUtils.getValue(LdapXMLUtils.host)+"/CRL_download.action").append("\n");
        config.append("CRLissuer              = dirName:issuer_sect").append("\n");
        config.append("reasons                = keyCompromise, CACompromise").append("\n");

        config.append("[issuer_sect]").append("\n");
        config.append("C                      = " + X509Context.default_country_code).append("\n");
        config.append("stateOrProvinceName    = " + x509Ca.getProvince()).append("\n");
        config.append("localityName           = " + x509Ca.getCity()).append("\n");
//        config.append("ST    = " + x509Ca.getProvince()).append("\n");
//        config.append("L           = " + x509Ca.getCity()).append("\n");
        config.append("CN                     = " + x509Ca.getCn()).append("\n");


        return config.toString();
    }

    /**
     * CA主配置文件信息
     *
     * @param x509Ca
     * @param storeDirectory
     * @return
     */
    public static String configCA(X509Ca x509Ca, String storeDirectory) {
        StringBuilder config = new StringBuilder();
        config.append("[ ca ]").append("\n");
        config.append("default_ca       = CA_default").append("\n");

        config.append("[ CA_default ]").append("\n");
        config.append("storeDirectory   = " + storeDirectory + "/" + x509Ca.getCn()).append("\n");
        config.append("certs            = $storeDirectory").append("\n");
        config.append("crl_dir          = $storeDirectory").append("\n");
        config.append("database         = $storeDirectory/"+ X509Context.database).append("\n");
        config.append("new_certs_dir    = $storeDirectory").append("\n");
        config.append("certificate      = "+ storeDirectory + "/" + x509Ca.getCn() + X509Context.certName).append("\n");
        config.append("serial           = $storeDirectory/"+ X509Context.serial_database).append("\n");
        config.append("crl              = "+ storeDirectory +"/"+ x509Ca.getCn() + ".crl  ").append("\n");
        config.append("crlnumber        = $storeDirectory/"+ X509Context.crl_database).append("\n");
        config.append("private_key      = "+ storeDirectory + "/" + x509Ca.getCn() + X509Context.keyName).append("\n");
        config.append("x509_extensions  = "+ X509Context.certificate_type_client).append("\n");
        config.append("crl_extensions   = "+ X509Context.crl_extends).append("\n");
        config.append("name_opt         = ca_default").append("\n");
        config.append("cert_opt         = ca_default").append("\n");
        config.append("default_days     = 365").append("\n");
        config.append("default_crl_days = 30").append("\n");
        config.append("default_md       = default").append("\n");
        config.append("preserve         = no").append("\n");
        config.append("policy           = policy_match").append("\n");

        config.append("[ policy_match ]").append("\n");
        config.append("countryName             = optional").append("\n");
        config.append("stateOrProvinceName     = optional").append("\n");
        config.append("organizationName        = optional").append("\n");
        config.append("organizationalUnitName  = optional").append("\n");
        config.append("commonName              = optional").append("\n");
        config.append("emailAddress            = optional").append("\n");

        config.append("[ policy_anything ]").append("\n");
        config.append("countryName             = optional").append("\n");
        config.append("stateOrProvinceName     = optional").append("\n");
        config.append("localityName            = optional").append("\n");
        config.append("organizationName        = optional").append("\n");
        config.append("organizationalUnitName  = optional").append("\n");
        config.append("commonName              = optional").append("\n");
        config.append("emailAddress            = optional").append("\n");


        /**
         * 根证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_ca +" ]").append("\n");
        config.append("basicConstraints              = CA:true").append("\n");
        config.append("subjectKeyIdentifier          = hash").append("\n");
        config.append("authorityKeyIdentifier        = keyid:always, issuer:always").append("\n");
        config.append("keyUsage                      = nonRepudiation, keyCertSign,cRLSign").append("\n");
        config.append("crlDistributionPoints         = "+ X509Context.crl_dps).append("\n");

        /**
         * 代码签名证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_codeSignature +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature").append("\n");
        config.append("extendedKeyUsage               = codeSigning").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * 计算机证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_computer +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,keyAgreement").append("\n");
        config.append("extendedKeyUsage               = serverAuth,clientAuth").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * WEB服务器证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_server +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("nsCertType                     = server").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement").append("\n");
        config.append("extendedKeyUsage               = serverAuth").append("\n");
        config.append("1.2.86.53525105.0.1            = DER:13:04:30:31:30:30").append("\n");
        config.append("1.2.86.53525105.0.2            = DER:13:04:30:31:62:30").append("\n");
        config.append("1.2.86.53525105.0.3            = DER:13:02:30:31").append("\n");
        config.append("1.2.86.53525105.0.4            = DER:13:04:30:30:30:33").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");


        /**
         * 客户端证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_client +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("nsCertType                     = client").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment").append("\n");
        config.append("extendedKeyUsage               = clientAuth").append("\n");
        config.append("1.2.86.53525105.0.1            = DER:13:04:30:31:30:30").append("\n");
        config.append("1.2.86.53525105.0.2            = DER:13:04:30:31:62:30").append("\n");
        config.append("1.2.86.53525105.0.3            = DER:13:02:30:31").append("\n");
        config.append("1.2.86.53525105.0.4            = DER:13:04:30:30:30:33").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * 信任列表签名证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_trustListSignature +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature").append("\n");
        config.append("extendedKeyUsage               = msCTLSign").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * 时间戳证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_timestamp +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment").append("\n");
        config.append("extendedKeyUsage               = timeStamping").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * IPSEC证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_ipsec +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment").append("\n");
        config.append("extendedKeyUsage               = 1.3.6.1.5.5.8.2.2").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * 安全Email证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_email +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("nsCertType                     = email").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment").append("\n");
        config.append("extendedKeyUsage               = emailProtection").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * 智能卡登陆证书  扩展
         */
        config.append("[ "+ X509Context.certificate_type_smartCardLogin +" ]").append("\n");
        config.append("basicConstraints               = CA:FALSE").append("\n");
        config.append("subjectKeyIdentifier           = hash").append("\n");
        config.append("authorityKeyIdentifier         = keyid, issuer:always").append("\n");
        config.append("keyUsage                       = digitalSignature,keyAgreement,decipherOnly").append("\n");
        config.append("extendedKeyUsage               = 1.3.6.1.4.1.311.10.3.11,msEFS,1.3.6.1.4.1.311.20.2.2").append("\n");
        config.append("crlDistributionPoints          = "+ X509Context.crl_dps).append("\n");

        /**
         * CRL  扩展
         */
        config.append("[ "+ X509Context.crl_extends +" ]").append("\n");
        config.append("authorityKeyIdentifier = keyid:always, issuer:always").append("\n");

        /**
         * 吊销列表发布点  扩展
         */
        config.append("["+ X509Context.crl_dps +"]").append("\n");
        config.append("fullname               = URI:http://" + LdapXMLUtils.getValue(LdapXMLUtils.host)+"/CRL_download.action").append("\n");
        config.append("CRLissuer              = dirName:issuer_sect").append("\n");
        config.append("reasons                = keyCompromise, CACompromise").append("\n");


        config.append("[issuer_sect]").append("\n");
        config.append("C                      = " + X509Context.default_country_code).append("\n");
        config.append("stateOrProvinceName    = " + x509Ca.getProvince()).append("\n");
        config.append("localityName           = " + x509Ca.getCity()).append("\n");
//        config.append("ST    = " + x509Ca.getProvince()).append("\n");
//        config.append("L           = " + x509Ca.getCity()).append("\n");
        config.append("CN                     = " + x509Ca.getCn()).append("\n");
        return config.toString();
    }

    /**
     * 构建CA请求文件
     *
     * @param x509Ca
     * @param storeDirectory
     * @return
     * @throws Exception
     */
    public static boolean buildCA(X509Ca x509Ca, String storeDirectory) {
        String s = applyCA(x509Ca);
        File file = new File(storeDirectory + "/" + x509Ca.getCn() + X509Context.config_type_certificate);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
        OutputStreamWriter osw = null;
        try {
            osw = new OutputStreamWriter(fos, X509Context.charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return false;
        }
        try {
            osw.write(s);
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

    /**
     * 构建CA主配置文件
     *
     * @param x509Ca
     * @param storeDirectory
     * @return
     * @throws Exception
     */
    public static boolean buildCAConfig(X509Ca x509Ca, String storeDirectory) {
        String ca_config_contents = configCA(x509Ca, storeDirectory);
        File txt = new File(storeDirectory + "/" + x509Ca.getCn() + "/" + x509Ca.getCn() + X509Context.config_type_ca);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(txt);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
        try {
            fos.write(ca_config_contents.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
       /* OutputStreamWriter osw  =   new OutputStreamWriter(fos,  X509Context.charset );
        osw.write(ca_config_contents);
        osw.flush();
        osw.close();*/
        if (!txt.exists()) {
            return false;
        }
        return true;
    }

    /**
     * 构建CA目录和数据库文件
     *
     * @param storeDirectory
     * @return
     * @throws Exception
     */
    public static boolean buildCADirectory(String storeDirectory) {
        File file = new File(storeDirectory);
        if (!file.exists())
            file.mkdirs();
        File f = new File(storeDirectory + "/" + X509Context.database);
        File crl_f = new File(storeDirectory+"/"+ X509Context.crl_database);
        File ser_f = new File(storeDirectory+"/"+ X509Context.serial_database);
        FileOutputStream stream = null;
        FileOutputStream crl_out = null;
        FileOutputStream ser_st = null;
        try {
            stream = new FileOutputStream(f);
            crl_out = new FileOutputStream(crl_f);
            ser_st =  new FileOutputStream(ser_f);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }
        OutputStreamWriter out = null;
        OutputStreamWriter out_crl  = null;
        OutputStreamWriter out_ser  = null;
        try {
            out = new OutputStreamWriter(stream, X509Context.charset);
            out_crl = new OutputStreamWriter(crl_out,  X509Context.charset );
            out_ser =  new OutputStreamWriter(ser_st,  X509Context.charset );
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return false;
        }
        try {
            out.write("");
            out.flush();
            out.close();
            out_crl.write("00");
            out_crl.flush();
            out_crl.close();

            out_ser.write("00");
            out_ser.flush();
            out_ser.close();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        if (f.exists()&&crl_f.exists()&&ser_f.exists())
            return true;
        else
            return false;
    }
}
