package com.hzih.ca.web.utils;

import org.apache.log4j.Logger;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class KeyStoreConvertUtils {
    private Logger log = Logger.getLogger(KeyStoreConvertUtils.class);

    /**
     * PFX证书转换为JKS(Java Key Store)
     * @param pfxPwd PFX证书密码
     * @param pfxFilePath PFX证书路径
     * @param jksPwd JKS证书密码
     * @param jksFilePath JKS证书路径
     */
    public boolean pfx2jks(String pfxFilePath, String pfxPwd, String jksFilePath, String jksPwd)throws Exception {
        boolean flag = false;
        FileInputStream fis = null;
        FileOutputStream out = null;
        try{
            KeyStore inputKeyStore = KeyStore.getInstance("PKCS12");
            fis = new FileInputStream(pfxFilePath);
            char[] inPassword = pfxPwd == null ? null : pfxPwd.toCharArray();
            char[] outPassword = jksPwd == null ? null : jksPwd.toCharArray();
            inputKeyStore.load(fis, inPassword);

            KeyStore outputKeyStore = KeyStore.getInstance("JKS");
            outputKeyStore.load(null, outPassword);
            Enumeration<String> enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()){
                String keyAlias = enums.nextElement();
                if (inputKeyStore.isKeyEntry(keyAlias)) {
                    Key key = inputKeyStore.getKey(keyAlias, inPassword);
                    Certificate[] certChain =  inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, pfxPwd.toCharArray(), certChain);
                }
            }
            out = new FileOutputStream(jksFilePath);
            outputKeyStore.store(out, outPassword);
            flag = true;
        }catch (Exception e){
            log.error(e.getMessage(),e);
        }finally{
            try{
                if (fis != null){
                    fis.close();
                }
                if (out != null){
                    out.close();
                }
            } catch (Exception e){
                log.error(e.getMessage(),e);
            }
        }
        return flag;
    }

    /**
     * 从JKS格式转换为PKCS12格式
     * @param jksFilePath String JKS格式证书库路径
     * @param jksPwd String JKS格式证书库密码
     * @param pfxFilePath String PKCS12格式证书库保存文件夹
     * @param pfxPwd String PKCS12格式证书库密码
     */
    public boolean jks2pfx(String jksFilePath, String jksPwd, String pfxFilePath, String pfxPwd)throws Exception{
        boolean flag = false;
        FileInputStream fis = null;
        try{
            KeyStore inputKeyStore = KeyStore.getInstance("JKS");
            fis = new FileInputStream(jksFilePath);
            char[] srcPwd = jksPwd == null ? null : jksPwd.toCharArray();
            char[] destPwd = pfxPwd == null ? null : pfxPwd.toCharArray();
            inputKeyStore.load(fis, srcPwd);

            KeyStore outputKeyStore = KeyStore.getInstance("PKCS12");
            Enumeration<String> enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()){
                String keyAlias =  enums.nextElement();
                outputKeyStore.load(null, destPwd);
                if (inputKeyStore.isKeyEntry(keyAlias)){
                    Key key = inputKeyStore.getKey(keyAlias, srcPwd);
                    java.security.cert.Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, destPwd, certChain);
                }
                FileOutputStream out = new FileOutputStream(pfxFilePath);
                outputKeyStore.store(out, destPwd);
                out.close();
                outputKeyStore.deleteEntry(keyAlias);
            }
            flag = true;
        } catch (Exception e){
            log.error(e.getMessage(),e);
        }finally{
            try{
                if (fis != null){
                    fis.close();
                }
            } catch (Exception e){
                log.error(e.getMessage(),e);
            }
        }
        return flag;
    }

    /**
     * 从BKS格式转换为PKCS12格式
     *
     * @param jksFilePath String JKS格式证书库路径
     * @param jksPwd String JKS格式证书库密码
     * @param pfxFilePath String PKCS12格式证书库保存文件夹
     * @param pfxPwd String PKCS12格式证书库密码
     */
    public boolean bks2pfx(String jksFilePath, String jksPwd, String pfxFilePath, String pfxPwd) throws Exception{
        boolean flag = false;
        FileInputStream fis = null;
        try{
            KeyStore inputKeyStore = KeyStore.getInstance("BKS",new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            fis = new FileInputStream(jksFilePath);
            char[] srcPwd = jksPwd == null ? null : jksPwd.toCharArray();
            char[] destPwd = pfxPwd == null ? null : pfxPwd.toCharArray();
            inputKeyStore.load(fis, srcPwd);

            KeyStore outputKeyStore = KeyStore.getInstance("PKCS12");
            Enumeration<String> enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()){
                String keyAlias = enums.nextElement();
                outputKeyStore.load(null, destPwd);
                if (inputKeyStore.isKeyEntry(keyAlias)) {
                    Key key = inputKeyStore.getKey(keyAlias, srcPwd);
                    java.security.cert.Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, destPwd,certChain);
                }
                FileOutputStream out = new FileOutputStream(pfxFilePath);
                outputKeyStore.store(out, destPwd);
                out.close();
                outputKeyStore.deleteEntry(keyAlias);
            }
            flag = true;
        }catch (Exception e){
            log.error(e.getMessage(),e);
        }finally{
            try{
                if (fis != null){
                    fis.close();
                }
            } catch (Exception e){
                log.error(e.getMessage(),e);
            }
        }
        return flag;
    }

    /**
     * 从PKCS12格式转换为BKS格式
     *
     * @param pfxFilePath String PKCS12格式证书库保存文件夹
     * @param pfxPwd String PKCS12格式证书库密码
     * @param bksFilePath String BKS格式证书库保存文件夹
     * @param bksPwd String BKS格式证书库密码
     */
    public boolean pfx2bks(String pfxFilePath, String pfxPwd, String bksFilePath, String bksPwd)throws Exception{
        boolean flag = false;
        FileInputStream fis = null;
        FileOutputStream out = null;
        try{
            KeyStore inputKeyStore = KeyStore.getInstance("PKCS12");
            fis = new FileInputStream(pfxFilePath);
            char[] inPassword = pfxPwd == null ? null : pfxPwd .toCharArray();
            char[] outPassword = bksPwd == null ? null : bksPwd.toCharArray();
            inputKeyStore.load(fis, inPassword);  
            
            KeyStore outputKeyStore = KeyStore.getInstance("BKS",new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            Enumeration<String> enums = inputKeyStore.aliases();
            while (enums.hasMoreElements()){
                String keyAlias =  enums.nextElement();
                outputKeyStore.load(null, outPassword);
                if (inputKeyStore.isKeyEntry(keyAlias)){
                    Key key = inputKeyStore.getKey(keyAlias, inPassword);
                    java.security.cert.Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
                    outputKeyStore.setKeyEntry(keyAlias, key, outPassword,certChain);
                }
                out = new FileOutputStream(bksFilePath);
                outputKeyStore.store(out, outPassword);
                out.close();
                outputKeyStore.deleteEntry(keyAlias);
            }
            flag = true;
        } catch (Exception e){
            log.error(e.getMessage(),e);
        }finally{
            try{
                if (fis != null){
                    fis.close();
                }
            } catch (Exception e){
                log.error(e.getMessage(),e);
            }
        }
        return flag;
    }

    /**
     * 列出JKS库内所有X509证书的属性
     *
     * @param jksFilePath 证书库路径
     * @param jksPwd 证书库密码
     * @param algName 库类型
     */
    public void listAllCertificates(String jksFilePath, String jksPwd, String algName){
        try{
            char[] srcPwd = jksPwd == null ? null : jksPwd.toCharArray();
            FileInputStream in = new FileInputStream(jksFilePath);
            KeyStore ks = KeyStore.getInstance(algName);
            ks.load(in, srcPwd);
            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()){
                String alias = e.nextElement();
                java.security.cert.Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate){
                    X509Certificate X509Cert = (X509Certificate) cert;
                    log.info("*********************************");
                    log.info("版本号:" + X509Cert.getVersion());
                    log.info("序列号:"+ X509Cert.getSerialNumber().toString(16));
                    log.info("主体名：" + X509Cert.getSubjectDN());
                    log.info("签发者：" + X509Cert.getIssuerDN());
                    log.info("有效期：" + X509Cert.getNotBefore());
                    log.info("签名算法：" + X509Cert.getSigAlgName());
                    log.info("输出证书信息:\n" + X509Cert.toString());
                    log.info("**************************************");

                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /*
    * 列出BKS库内所有X509证书的属性
    * @param jksFilePath 证书库路径
    * @param jksPwd 证书库密码
    * @param algName 库类型
    */
    public void listAllCertificatesBks(String jksFilePath, String jksPwd, String algName){
        try{
            char[] srcPwd = jksPwd == null ? null : jksPwd.toCharArray();
            FileInputStream in = new FileInputStream(jksFilePath);
            KeyStore ks = KeyStore.getInstance(algName,new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            ks.load(in, srcPwd);
            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()){
                String alias = e.nextElement();
                java.security.cert.Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate){
                    X509Certificate X509Cert = (X509Certificate) cert;
                    log.info("*********************************");
                    log.info("版本号:" + X509Cert.getVersion());
                    log.info("序列号:" + X509Cert.getSerialNumber().toString(16));
                    log.info("主体名：" + X509Cert.getSubjectDN());
                    log.info("签发者：" + X509Cert.getIssuerDN());
                    log.info("有效期：" + X509Cert.getNotBefore());
                    log.info("签名算法：" + X509Cert.getSigAlgName());
                    log.info("输出证书信息:\n" + X509Cert.toString());
                    log.info("**************************************");
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }
}