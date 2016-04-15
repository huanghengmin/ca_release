package com.hzih.ca.web.action.ca;

import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.mapper.json.X509CaAttrJsonMapper;
import com.hzih.ca.service.X509CaService;
import com.hzih.ca.service.LogService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;
import com.hzih.ca.web.utils.*;
import com.hzih.ca.web.utils.X509CAConfigUtils;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-7-30
 * Time: 上午10:29
 * To change this template use File | Settings | File Templates.
 */
public class X509CaAction extends ActionSupport {
    private static Logger logger = Logger.getLogger(X509CaAction.class);
    private X509Ca x509Ca;
    private X509CaService x509CaService;
    private LogService logService;

    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public X509CaService getX509CaService() {
        return x509CaService;
    }

    public void setX509CaService(X509CaService x509CaService) {
        this.x509CaService = x509CaService;
    }

    public X509Ca getX509Ca() {
        return x509Ca;
    }

    public void setX509Ca(X509Ca x509Ca) {
        this.x509Ca = x509Ca;
    }

    /**
     * 检查根证书是否存在
     *
     * @return
     * @throws Exception
     */
    public String existCa() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        String cn = request.getParameter(X509Ca.getCnAttr());
        String json = null;
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        NamingEnumeration results = context.search(LdapXMLUtils.getValue(LdapXMLUtils.base), X509Ca.getCnAttr() + "=" + cn, sc);
        if (results.hasMore()) {
            json = "{success:true,msg:'false'}";
        } else {
            json = "{success:true,msg:'true'}";
        }
        context.close();
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 下载证书
     *
     * @return
     * @throws Exception
     */
    public String downloadCaPem() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String DN = X509CaXML.getSignDn();
        //签发CA CN
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String name = null;
        String subPath = null;
        subPath = dir + CN + X509Context.certName;
        name = CN + X509Context.certName;
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        //得到用户的浏览器名  MSIE  Firefox
        String userBrowser = st.nextToken();
        File file = new File(subPath);
        FileUtil.downType(response, name, userBrowser);
        response = FileUtil.copy(file, response);
        json = "{success:true}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String downloadCaIE() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        //签发CA DN
        String DN = X509CaXML.getSignDn();
        //签发CA CN
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String name = null;
        String subPath = null;

        subPath = dir + CN + X509Context.certName;
        name = CN + X509Context.certName;
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        //得到用户的浏览器名  MSIE  Firefox
        String userBrowser = st.nextToken();
        File file = new File(subPath);
        CertificateUtils certificateUtils = new CertificateUtils();
        X509Certificate certificate = certificateUtils.get_x509_certificate(file);
        if (certificate != null) {
            byte[] res = certificate.getEncoded();
            FileUtil.downType(response, name, userBrowser);
            ServletOutputStream out = response.getOutputStream();
            out.write(res);
            out.flush();
            out.close();
            json = "{success:true}";
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String downloadCaBks() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String DN = X509CaXML.getSignDn();
        //签发CA CN
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String name = null;
        String subPath = null;
        subPath = dir + CN + X509Context.bksName;
        name = CN + X509Context.bksName;
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        //得到用户的浏览器名  MSIE  Firefox
        String userBrowser = st.nextToken();
        File file = new File(subPath);
        FileUtil.downType(response, name, userBrowser);
        response = FileUtil.copy(file, response);
        json = "{success:true}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String downloadCaJks() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String DN = X509CaXML.getSignDn();
        //签发CA CN
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String name = null;
        String subPath = null;
        subPath = dir + CN + X509Context.jksName;
        name = CN + X509Context.jksName;
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        //得到用户的浏览器名  MSIE  Firefox
        String userBrowser = st.nextToken();
        File file = new File(subPath);
        FileUtil.downType(response, name, userBrowser);
        response = FileUtil.copy(file, response);
        json = "{success:true}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String show_certificate()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        SimpleDateFormat format = new SimpleDateFormat("yyyy年MM日dd日HH时mm分ss秒");
        String DN = X509CaXML.getSignDn();
        //签发CA CN
        String CN = DirectoryUtils.getCNForDN(DN);
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String subPath = dir + CN + X509Context.certName;
        File file = new File(subPath);
        StringBuilder json = new StringBuilder();
        CertificateFactory  certificatefactory = CertificateFactory.getInstance("X.509");
        FileInputStream server = new FileInputStream(file);
        X509Certificate cert = (X509Certificate)certificatefactory.generateCertificate(server);
        String  subject  = cert.getSubjectDN().getName();
        int version = cert.getVersion();
        String issue = cert.getIssuerDN().toString();
        String serial = cert.getSerialNumber().toString(16).toUpperCase();
        Date notBefore=cert.getNotBefore();//得到开始有效日期
        Date notAfter = cert.getNotAfter();  //得到截止日期
        String s_notBefore="";
        String s_notAfter="";
        if(null!=notBefore){
            s_notBefore = format.format(notBefore);
        }
        if(null!=notBefore){
            s_notAfter = format.format(notAfter);
        }
        json.append("{").append("subject:'"+subject+"',version:'V"+version+"',issue:'"+issue+"',serial:'"+serial+"',before:'"+s_notBefore+"',after:'"+s_notAfter+"'}");
        StringBuilder json2 = new StringBuilder("{totalCount:" + 1 + ",root:[");
        json2.append(json);
        json2.append("]}");
        actionBase.actionEnd(response, json2.toString(), result);
        return null;
    }

    /**
     * 自签发证书
     */
    public String selfSign() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        //数据DN
        String DN = DNUtils.add(LdapXMLUtils.getValue(LdapXMLUtils.base), x509Ca.getCn());
        //获取CA签发目录
        String signDirectory = DirectoryUtils.getDNDirectory(DN);
        //CA证书存放路径
        String selfDirectory = DirectoryUtils.getSuperStoreDirectory(signDirectory);
        //建立目录结构
        boolean flag = X509CAConfigUtils.buildCADirectory(signDirectory);
        if (flag) {
            //构建ca请求文件
            flag = X509CAConfigUtils.buildCA(x509Ca, selfDirectory);
            if (flag) {
                //生成主配置文件
                flag = X509CAConfigUtils.buildCAConfig(x509Ca, selfDirectory);
                if (flag) {
                    //签发根证书
                    flag = X509ShellUtils.build_selfsign_ca(x509Ca.getValidity(), x509Ca.getKeyLength(), selfDirectory + "/" + x509Ca.getCn() + X509Context.keyName, selfDirectory + "/" + x509Ca.getCn() + X509Context.certName, selfDirectory + "/" + x509Ca.getCn() + X509Context.config_type_certificate);
                    if (flag) {
                        File key_file = new File(selfDirectory + "/" + x509Ca.getCn() + X509Context.keyName);
                        if (key_file.exists()) {
                            //读取私钥文件
//                            String key = FileHandles.readFileByLines(key_file);
                            //读取证书文件
                            File cer_file = new File(selfDirectory + "/" + x509Ca.getCn() + X509Context.certName);
                            if (cer_file.exists()) {
                                //证书文件内容
//                                String certBase64Code = FileHandles.readFileByLines(cer_file);
                                //构建根CA——BKS文件
//                                    caUtils.mkRootBksShell(path,fatherLiunxPath,CN);
                                CertificateUtils certificateUtils = new CertificateUtils();
                                X509Certificate cert = certificateUtils.get_x509_certificate(cer_file);
                                x509Ca.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                                x509Ca.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                                x509Ca.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                                x509Ca.setCertStatus("0");
                                x509Ca.setDn(DN);
//                                x509Ca.setKey(key);
//                                x509Ca.setCertBase64Code(certBase64Code);
                                //
                                x509Ca.setcACertificateAttr(cert.getEncoded());
                                LdapUtils ldapUtils = new LdapUtils();
                                DirContext ctx = ldapUtils.getCtx();
                                try {
                                    flag = x509CaService.add(ctx, x509Ca);
                                    if (flag) {
                                        flag = X509CaXML.save(x509Ca);
                                        if (flag) {
                                            msg = "签发CA成功,通用名:" + x509Ca.getCn();
                                            json = "{success:true,msg:'" + msg + "'}";
                                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                                        } else {
                                            msg = "签发CA失败,CA信息文件写入出现错误,通用名:" + x509Ca.getCn();
                                            json = "{success:false,msg:'" + msg + "'}";
                                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                                        }
                                    } else {
                                        msg = "签发CA失败,保存CA到LDAP出错,通用名:" + x509Ca.getCn();
                                        json = "{success:false,msg:'" + msg + "'}";
                                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                                    }
                                } catch (Exception e) {
                                    logger.error(e.getMessage(),e);
                                    msg = "签发CA失败,保存CA到LDAP出错,通用名:" + x509Ca.getCn();
                                    json = "{success:false,msg:'" + msg + "'}";
                                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                                } finally {
                                    LdapUtils.close(ctx);
                                }
                            } else {
                                msg = "签发CA失败,证书文件未生成,通用名:" + x509Ca.getCn();
                                json = "{success:false,msg:'" + msg + "'}";
                                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                            }
                        } else {
                            msg = "签发CA失败,私钥文件未生成,通用名:" + x509Ca.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                        }
                    } else {
                        msg = "签发CA失败,签发CA出现错误,通用名:" + x509Ca.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                    }
                } else {
                    msg = "签发CA失败,CA信息配置出错,请确定CA信息正确填写,通用名:" + x509Ca.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
                }
            } else {
                msg = "签发CA失败,CA信息配置出错,请确定CA信息正确填写且未包含特殊字符,通用名:" + x509Ca.getCn();
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
            }
        } else {
            msg = "签发CA失败,构建CA目录出错,通用名:" + x509Ca.getCn();
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "CA", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }


    /**
     * 查找签发证书
     *
     * @return
     * @throws Exception
     */
    public String findSelf() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        if (context != null) {
            StringBuilder sb = new StringBuilder("(" + X509Ca.getCnAttr() + "=" + X509CaXML.getValue(X509CaXML.cn) + ")");
            List<SearchResult> resultList = new ArrayList<>();
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration results = context.search(LdapXMLUtils.getValue(LdapXMLUtils.base), sb.toString(), sc);
            int totalCount = 0;
            StringBuilder json = new StringBuilder();
            while (results.hasMore()) {
                SearchResult sr = (SearchResult) results.next();
                resultList.add(sr);
                //得到所有返回数据
                json.append(X509CaAttrJsonMapper.mapJsonFromAttr(sr));
                if (results.hasMore()) {
                    json.append(",");
                }
                totalCount++;
            }
            StringBuilder json2 = new StringBuilder("{totalCount:" + totalCount + ",root:[");
            json2.append(json);
            json2.append("]}");
            actionBase.actionEnd(response, json2.toString(), result);
        }
        ldapUtils.close(context);
        return null;
    }
}