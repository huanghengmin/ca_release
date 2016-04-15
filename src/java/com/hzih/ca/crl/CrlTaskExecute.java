package com.hzih.ca.crl;

import com.hzih.ca.dao.X509CaDao;
import com.hzih.ca.dao.impl.X509CaDaoImpl;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.utils.*;
import org.apache.log4j.Logger;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-9-17
 * Time: 下午5:06
 * To change this template use File | Settings | File Templates.
 */
public class CrlTaskExecute {

    private Logger logger = Logger.getLogger(CrlTaskExecute.class);

    public void CRL() {
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
                    logger.info("CRL创建成功,时间:" + new Date());
                }
            } catch (Exception e) {
                logger.info("CRL创建失败,时间:" + new Date(),e);
            } finally {
                LdapUtils.close(ctx);
            }
        } else {
            logger.info("CRL创建失败,时间:" + new Date());
        }
    }
}
