package com.hzih.ca.web.action.crl;

import com.hzih.ca.dao.X509CaDao;
import com.hzih.ca.dao.impl.X509CaDaoImpl;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.service.LogService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.StringTokenizer;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 12-11-8
 * Time: 下午11:19
 * To change this template use File | Settings | File Templates.
 */
public class MakeCRLAction extends ActionSupport {
    private Logger logger = Logger.getLogger(MakeCRLAction.class);
    private LogService logService;

    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public String createCRL() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String msg = null;
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
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


    public String downloadCRL() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到liunx路径
        String liunxPath = DirectoryUtils.getDNDirectory(DN);
        //得到子CA在liunx下的路径
        String childLiunxPath = DirectoryUtils.getSuperStoreDirectory(liunxPath);
        //得到父CA在liunx下的路径
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        String userBrowser = st.nextToken();
        //得到用户的浏览器名  MSIE  Firefox
        File file = new File(childLiunxPath + "/" + CN + X509Context.crlName);
        if (file.exists()) {
            String name = file.getName();
            FileUtil.downType(response, name, userBrowser);
            json = "{success:true}";
            response = FileUtil.copy(file, response);
        } else {
            json = "{success:false}";
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }
}
