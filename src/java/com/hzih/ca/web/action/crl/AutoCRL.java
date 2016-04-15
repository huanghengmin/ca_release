package com.hzih.ca.web.action.crl;

import com.hzih.ca.dao.X509CaDao;
import com.hzih.ca.dao.impl.X509CaDaoImpl;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.utils.DirectoryUtils;
import com.hzih.ca.web.utils.X509ShellUtils;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-4
 * Time: 上午9:14
 * To change this template use File | Settings | File Templates.
 */
public class AutoCRL {

    public static boolean CRL() {
        //
        String DN = X509CaXML.getSignDn();
        //
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到liunx路径
        String liunxPath = DirectoryUtils.getDNDirectory(DN);
        //得到子CA在liunx下的路径
        String childLiunxPath = DirectoryUtils.getSuperStoreDirectory(liunxPath);
        //得到父CA在liunx下的路径
        boolean flag = X509ShellUtils.build_make_crl(childLiunxPath + "/" + CN + X509Context.crlName, childLiunxPath + "/" + CN + X509Context.keyName, childLiunxPath + "/" + CN + X509Context.certName, childLiunxPath + "/" + CN + "/" + CN + X509Context.config_type_ca);
        if (flag) {
//得到父ca结果集
            SearchResult fatherResults = LdapUtils.findCurrentNode(DN);
            //获取上组签发CA
            LdapUtils ldapUtils = new LdapUtils();
            DirContext ctx = ldapUtils.getCtx();
            try {
                X509Ca x509Ca = X509CaAttributeMapper.mapFromAttributes(fatherResults);
                File file = new File(childLiunxPath + "/" + CN + X509Context.crlName);
                if (file.exists()) {
                    FileInputStream fis = new FileInputStream(file);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509CRL aCrl = (X509CRL) cf.generateCRL(fis);
                    byte[] crl_bytes = aCrl.getEncoded();
                    x509Ca.setCertificateRevocationListAttr(crl_bytes);
//                    x509Ca.setAuthorityRevocationListAttr(crl_bytes);
//                    x509Ca.setDeltaRevocationListAttr(crl_bytes);
                    X509CaDao x509CaDao = new X509CaDaoImpl();
                    x509CaDao.modify(ctx, x509Ca);
                    return true;
                }
            } catch (Exception e) {

                e.printStackTrace();
                return false;
            } finally {
                LdapUtils.close(ctx);
            }
        } else {
            return false;
        }
        return false;
    }
}
