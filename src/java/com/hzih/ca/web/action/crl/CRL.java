package com.hzih.ca.web.action.crl;

import com.hzih.ca.dao.X509CaDao;
import com.hzih.ca.dao.impl.X509CaDaoImpl;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.service.LogService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.StringContext;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.utils.DirectoryUtils;
import com.hzih.ca.web.utils.X509ShellUtils;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 13-10-21
 * Time: 下午8:12
 * To change this template use File | Settings | File Templates.
 */
public class CRL extends ActionSupport {
    private Logger logger = Logger.getLogger(CRL.class);
    private LogService logService;
    private Logger log = Logger.getLogger(CRL.class);


    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }


    public String down_crl() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        String DN = X509CaXML.getSignDn();
        String CN = DirectoryUtils.getCNForDN(DN);
        String dir = DirectoryUtils.getSuperDirectory(DN);
//        String name = null;
        String subPath = null;
        subPath = dir + CN + X509Context.crlName;
//        name = CN + X509Context.crlName;
        File file = new File(subPath);
        if (file.exists())
            response = FileUtil.copy(file, response);
        return null;
    }

    /**
     * 下载CRL列表文件
     *
     * @return
     * @throws Exception
     */
    public String download() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        String json = "{success:false}";
        String DN = X509CaXML.getSignDn();

        String CN = DirectoryUtils.getCNForDN(DN);

        String dir = DirectoryUtils.getSuperDirectory(DN);
        String name = null;
        String subPath = null;
        subPath = dir + CN + X509Context.crlName;
        name = CN + X509Context.crlName;
        File file = new File(subPath);

        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = null;
        if (Agent != null) {
            st = new StringTokenizer(Agent, ";");
            st.nextToken();
            //得到用户的浏览器名  MSIE  Firefox
            String userBrowser = st.nextToken();
            FileUtil.downType(response, name, userBrowser);
        }
        response = FileUtil.copy(file, response);
        json = "{success:true}";
        PrintWriter writer = response.getWriter();
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }

    public String readCRL() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        //获取签发DN
        String DN = X509CaXML.getSignDn();
        //获取签发CN
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到liunx路径
        String liunxPath = DirectoryUtils.getDNDirectory(DN);
        //得到子CA在liunx下的路径
        String childLiunxPath = DirectoryUtils.getSuperStoreDirectory(liunxPath);
        //对应CRL列表文件
        File file = new File(childLiunxPath + "/" + CN + X509Context.crlName);
        if (file.exists()) {
            FileInputStream fis = new FileInputStream(file);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL aCrl = (X509CRL) cf.generateCRL(fis);
            if (aCrl != null) {
                Date nextUpdate = aCrl.getNextUpdate();
                Date thisUpdate = aCrl.getThisUpdate();
               /* Set tSet = aCrl.getRevokedCertificates();
                if(tSet!=null){
                    Iterator tIterator = tSet.iterator();
                    while (tIterator!=null&&tIterator.hasNext()) {
                        X509CRLEntry tEntry = (X509CRLEntry) tIterator.next();
                        String sn = tEntry.getSerialNumber().toString(16).toUpperCase();
                        String issName = aCrl.getIssuerDN().toString();
                        String time = new SimpleDateFormat("yyyy年MM月dd日HH时mm分ss秒").format(tEntry .getRevocationDate());
                        log.info("*******************************************吊销信息*******************************************");
                        log.info(sn);
                        log.info(issName);
                        log.info(time);
                        log.info("*******************************************吊销信息*******************************************");
                    }
                }*/
            }
        }
        return null;
    }

    public String createCRL() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        String DN = X509CaXML.getSignDn();
        String CN = DirectoryUtils.getCNForDN(DN);
        String childLiunxPath = DirectoryUtils.getSuperDirectory(DN);
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
                    msg = "CRL列表创建成功";
                    json = "{success:true,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "创建CRL", msg);
                }
            } catch (Exception e) {
                logger.error(e.getMessage(),e);
                msg = "CRL列表创建失败";
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "创建CRL", msg);
            } finally {
                LdapUtils.close(ctx);
            }


        } else {
            msg = "CRL列表创建失败";
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "创建CRL", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }
}
