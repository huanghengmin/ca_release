package com.hzih.ca.web.action.server;

import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.X509Server;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.entity.mapper.json.X509ServerAttrJsonMapper;
import com.hzih.ca.service.LogService;
import com.hzih.ca.service.X509ServerService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.crl.AutoCRL;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.action.lisence.LicenseXML;
import com.hzih.ca.web.utils.*;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import sun.security.x509.X500Name;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-6-30
 * Time: 下午3:12
 * To change this template use File | Settings | File Templates.
 */
public class X509ServerAction extends ActionSupport {
    private Logger logger = Logger.getLogger(X509ServerAction.class);
    private X509Server x509Server;
    private File uploadFile;
    private String uploadFileFileName;
    private String uploadFileContentType;
    private LogService logService;

    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public File getUploadFile() {
        return uploadFile;
    }

    public void setUploadFile(File uploadFile) {
        this.uploadFile = uploadFile;
    }

    public String getUploadFileFileName() {
        return uploadFileFileName;
    }

    public void setUploadFileFileName(String uploadFileFileName) {
        this.uploadFileFileName = uploadFileFileName;
    }

    public String getUploadFileContentType() {
        return uploadFileContentType;
    }

    public void setUploadFileContentType(String uploadFileContentType) {
        this.uploadFileContentType = uploadFileContentType;
    }

    public X509Server getX509Server() {
        return x509Server;
    }

    public void setX509Server(X509Server x509Server) {
        this.x509Server = x509Server;
    }

    private X509ServerService x509ServerService;

    public X509ServerService getX509ServerService() {
        return x509ServerService;
    }


    public void setX509ServerService(X509ServerService x509ServerService) {
        this.x509ServerService = x509ServerService;
    }

    /**
     * 查找数据库是否已存在记录
     *
     * @return
     * @throws Exception
     */
    public String existServer() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String cn = request.getParameter("cn");
        LdapUtils ldapUtils = new LdapUtils();
        DirContext ctx = ldapUtils.getCtx();
        String json = null;
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        NamingEnumeration results = ctx.search(X509CaXML.getSignDn(), X509Server.getCnAttr() + "=" + cn, sc);
        if (results.hasMore()) {
            json = "{success:true,flag:'false'}";
        } else {
            json = "{success:true,flag:'true'}";
        }
        ctx.close();

        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 添加
     *
     * @return
     * @throws Exception
     */
    public String signServer() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String msg = null;
        String json = null;
        //签发DN
        String signDn = X509CaXML.getSignDn();
        //数据DN
        String DN = DNUtils.add(signDn, x509Server.getCn());
        //根据DN获取系统存储路径
        String realDirectory = DirectoryUtils.getDNDirectory(DN);
        //得到父CA名称
        String signCn = DirectoryUtils.getCNSuper(signDn);
        //得到子CA在liunx下的路径
        String storeDirectory = DirectoryUtils.getSuperStoreDirectory(realDirectory);
        //得到父CA在liunx下的路径
        String superStoreDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
        //得到父ca结果集
        SearchResult fatherResults = LdapUtils.findSuperNode(DN);
        //获取上组签发CA
        X509Ca x509Ca = X509CaAttributeMapper.mapFromAttributes(fatherResults);
        //构建用户请求文件
        boolean flag = X509ServerConfigUtils.buildServer(x509Server, storeDirectory);
        if (flag) {
            //构建csr请求
            flag = X509ShellUtils.build_csr(x509Ca.getKeyLength(), storeDirectory + "/" + x509Server.getCn() + X509Context.keyName, storeDirectory + "/" + x509Server.getCn() + X509Context.csrName, storeDirectory + "/" + x509Server.getCn() + X509Context.config_type_certificate);
            if (flag) {
                //签发用户CA
                flag = X509ShellUtils.build_sign_csr(storeDirectory + "/" + x509Server.getCn() + X509Context.csrName, storeDirectory + "/" + signCn + X509Context.config_type_ca, X509Context.certificate_type_server, superStoreDirectory + "/" + signCn + X509Context.certName, superStoreDirectory + "/" + signCn + X509Context.keyName, storeDirectory + "/" + x509Server.getCn() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                if (flag) {
                    //构建pfx文件
                    flag = X509ShellUtils.build_pkcs12(storeDirectory + "/" + x509Server.getCn() + X509Context.keyName, storeDirectory + "/" + x509Server.getCn() + X509Context.certName, storeDirectory + "/" + x509Server.getCn() + X509Context.pkcsName);
                    if (flag) {
//                        String key = FileHandles.readFileByLines(storeDirectory + "/" + x509Server.getCn() + X509Context.keyName);
                        File cerFile = new File(storeDirectory + "/" + x509Server.getCn() + X509Context.certName);
//                        String certificate = null;
//                        if (cerFile.exists())
//                            certificate = FileHandles.readFileByLines(cerFile);
                        if (cerFile.exists() && cerFile.length() > 0) {
                            CertificateUtils certificateUtils = new CertificateUtils();
                            X509Certificate cert = certificateUtils.get_x509_certificate(cerFile);
                            x509Server.setCertStatus("0");
                            x509Server.setIssueCa(signDn);
//                            x509Server.setKey(key);
//                            x509Server.setCertBase64Code(certificate);
                            x509Server.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                            x509Server.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                            x509Server.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                            //
                            x509Server.setUserCertificateAttr(cert.getEncoded());
                            boolean save_flag = x509ServerService.add(x509Server);
                            if (save_flag) {
                                msg = "签发设备证书成功,通用名:" + x509Server.getCn();
                                json = "{success:true,msg:'" + msg + "'}";
                                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                            } else {
                                msg = "签发设备证书失败,通用名:" + x509Server.getCn();
                                json = "{success:false,msg:'" + msg + "'}";
                                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                            }
                        } else {
                            msg = "签发设备证书失败,保存到LDAP数据库失败,通用名:" + x509Server.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                        }
                    } else {
                        msg = "签发设备证书失败,构建PKCS文件出现错误,通用名:" + x509Server.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                    }
                } else {
                    msg = "签发设备证书失败,签发时出现错误,通用名:" + x509Server.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                }
            } else {
                msg = "签发设备证书失败,构建设备信息时出现错误,请确定用户信息填写正确,且未包含特殊字符!,通用名:" + x509Server.getCn();
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
            }
        } else {
            msg = "签发设备证书失败,请确定设备信息填写正确,通用名:" + x509Server.getCn();
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String parseRequest() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String msg = null;
        String json = null;
        if (uploadFile != null) {
            try {
                PKCS10CertificationRequest pkcs10 = CertificateUtils.getPKCS10CertificationRequest(uploadFile);
                X509Name name = pkcs10.getCertificationRequestInfo().getSubject();
                Vector V_C = name.getValues(X509Name.C);
                Vector V_CN = name.getValues(X509Name.CN);
                Vector V_ST = name.getValues(X509Name.ST);
                Vector V_L = name.getValues(X509Name.L);
                Vector V_O = name.getValues(X509Name.O);
                Vector V_OU = name.getValues(X509Name.OU);
                Vector V_E = name.getValues(X509Name.E);
                StringBuilder v_C_b = null;
                StringBuilder v_CN_b = null;
                StringBuilder v_ST_b = null;
                StringBuilder v_L_b = null;
                StringBuilder v_O_b = null;
                StringBuilder v_OU_b = null;
                StringBuilder v_E_b = null;


                if (V_C != null && V_C.size() > 0) {
                    Object v_c = V_C.get(0);
                    if (v_c != null) {
                        v_C_b = new StringBuilder();
                        v_C_b.append("C:'");
                        v_C_b.append(v_c.toString());
                        v_C_b.append("'");
                    }
                }

                if (V_CN != null && V_CN.size() > 0) {
                    Object v_c = V_CN.get(0);
                    if (v_c != null) {
                        v_CN_b = new StringBuilder();
                        v_CN_b.append("CN:'");
                        v_CN_b.append(v_c.toString());
                        v_CN_b.append("'");
                    }
                }

                if (V_ST != null && V_ST.size() > 0) {
                    Object v_c = V_ST.get(0);
                    if (v_c != null) {
                        v_ST_b = new StringBuilder();
                        v_ST_b.append("ST:'");
                        v_ST_b.append(v_c.toString());
                        v_ST_b.append("'");
                    }
                }

                if (V_L != null && V_L.size() > 0) {
                    Object v_c = V_L.get(0);
                    if (v_c != null) {
                        v_L_b = new StringBuilder();
                        v_L_b.append("L:'");
                        v_L_b.append(v_c.toString());
                        v_L_b.append("'");
                    }
                }

                if (V_O != null && V_O.size() > 0) {
                    Object v_c = V_O.get(0);
                    if (v_c != null) {
                        v_O_b = new StringBuilder();
                        v_O_b.append("O:'");
                        v_O_b.append(v_c.toString());
                        v_O_b.append("'");
                    }
                }

                if (V_OU != null && V_OU.size() > 0) {
                    Object v_c = V_OU.get(0);
                    if (v_c != null) {
                        v_OU_b = new StringBuilder();
                        v_OU_b.append("OU:'");
                        v_OU_b.append(v_c.toString());
                        v_OU_b.append("'");
                    }
                }

                if (V_E != null && V_E.size() > 0) {
                    Object v_c = V_E.get(0);
                    if (v_c != null) {
                        v_E_b = new StringBuilder();
                        v_E_b.append("E:'");
                        v_E_b.append(v_c.toString());
                        v_E_b.append("'");
                    }
                }

                StringBuilder sb = new StringBuilder();
                if (v_C_b != null) {
                    sb.append(v_C_b);
                    sb.append(",");
                }

                if (v_CN_b != null) {
                    sb.append(v_CN_b);
                    sb.append(",");
                }

                if (v_ST_b != null) {
                    sb.append(v_ST_b);
                    sb.append(",");
                }

                if (v_L_b != null) {
                    sb.append(v_L_b);
                    sb.append(",");
                }

                if (v_O_b != null) {
                    sb.append(v_O_b);
                    sb.append(",");
                }

                if (v_OU_b != null) {
                    sb.append(v_OU_b);
                    sb.append(",");
                }

                if (v_E_b != null) {
                    sb.append(v_E_b);
                    sb.append(",");
                }

                if (sb.toString().endsWith(",")) {
                    String sb_json = sb.substring(0, sb.toString().length() - 1);
                    if (sb_json.length() > 0) {
                        msg = "解析证书请求成功!";
                        json = "{success:true,flag:true," + sb_json + ",msg:'" + msg + "'}";
                    }
                }

            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                msg = "解析证书请求信息失败,请确定请求文件格式及内容!";
                json = "{success:true,flag:false,msg:'" + msg + "'}";
            }
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String signRequest() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String command = request.getParameter("command");
        String msg = null;
        String json = null;
        boolean flag = LicenseXML.readLicense(2);
        if (flag) {
            //签发DN
            String signDn = X509CaXML.getSignDn();
            //数据DN
            String DN = DNUtils.add(signDn, x509Server.getCn());
            //根据DN获取系统存储路径
            String realDirectory = DirectoryUtils.getDNDirectory(DN);
            //得到父CA名称
            String signCn = DirectoryUtils.getCNSuper(signDn);
            //得到子CA在liunx下的路径
            String storeDirectory = DirectoryUtils.getSuperStoreDirectory(realDirectory);
            //得到父CA在liunx下的路径
            String superStoreDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
            //得到父ca结果集
//        SearchResult fatherResults = LdapUtils.findSuperNode(DN);
            //获取上组签发CA
//        X509Ca x509Ca = X509CaAttributeMapper.mapFromAttributes(fatherResults);
            //构建用户请求文件
//        boolean flag = X509ServerConfigUtils.buildServer(x509Server, storeDirectory);
            if (uploadFile != null) {
                FileUtil.copy(uploadFile, storeDirectory + "/" + x509Server.getCn() + X509Context.csrName);
                File file = new File(storeDirectory + "/" + x509Server.getCn() + X509Context.csrName);
                if (file.exists()) {
                    flag = true;
                }
            }
            if (flag) {
                //构建csr请求
//            flag = X509ShellUtils.build_csr(x509Ca.getKeyLength(), storeDirectory + "/" + x509Server.getCn() + X509Context.keyName, storeDirectory + "/" + x509Server.getCn() + X509Context.csrName, storeDirectory + "/" + x509Server.getCn() + X509Context.config_type_certificate);
//            if (flag) {
                //签发用户CA
                flag = X509ShellUtils.build_sign_csr(storeDirectory + "/" + x509Server.getCn() + X509Context.csrName, storeDirectory + "/" + signCn + X509Context.config_type_ca, X509Context.certificate_type_server, superStoreDirectory + "/" + signCn + X509Context.certName, superStoreDirectory + "/" + signCn + X509Context.keyName, storeDirectory + "/" + x509Server.getCn() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                if (flag) {
                    //构建pfx文件
                    //flag = X509ShellUtils.build_pkcs12(storeDirectory + "/" + x509Server.getCn() + X509Context.keyName, storeDirectory + "/" + x509Server.getCn() + X509Context.certName, storeDirectory + "/" + x509Server.getCn() + X509Context.pkcsName);
//                if (flag) {
//                    String key = FileHandles.readFileByLines(storeDirectory + "/" + x509Server.getCn() + X509Context.keyName);
                    File cerFile = new File(storeDirectory + "/" + x509Server.getCn() + X509Context.certName);
//                    String certificate = null;
//                    if (cerFile.exists())
//                        certificate = FileHandles.readFileByLines(cerFile);
                    if (cerFile.exists() && cerFile.length() > 0) {
                        CertificateUtils certificateUtils = new CertificateUtils();
                        X509Certificate cert = certificateUtils.get_x509_certificate(cerFile);
                        x509Server.setCertStatus("0");
                        x509Server.setIssueCa(signDn);
                        x509Server.setDn(DNUtils.add(signDn, x509Server.getCn()));
                        //                    x509Server.setKey(key);
//                        x509Server.setCertBase64Code(certificate);
                        x509Server.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                        x509Server.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                        x509Server.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                        //
                        x509Server.setUserCertificateAttr(cert.getEncoded());
                        boolean option_flag = false;
                        if (command.equals("add")) {
                            option_flag = x509ServerService.add(x509Server);
                        } else if (command.equals("update")) {
                            option_flag = x509ServerService.modify(x509Server);
                        }
                        if (option_flag) {
                            LicenseXML.addLicense(2);
                            msg = "签发设备证书请求成功,通用名:" + x509Server.getCn();
                            json = "{success:true,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                        } else {
                            msg = "签发设备证书请求失败,通用名:" + x509Server.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                        }
                    } else {
                        msg = "签发设备证书请求失败,证书文件未生成,通用名:" + x509Server.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                    }
//                }
                } else {
                    msg = "签发设备证书请求失败,请确定信息文件未包含特殊字符,通用名:" + x509Server.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                }
//            }
            } else {
                msg = "签发设备证书请求失败,设备证书请求文件存储失败,通用名:" + x509Server.getCn();
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
            }
        } else {
            msg = "license名额已达上限,无法签发证书";
            json = "{success:false,msg:'" + msg + "'}";
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 删除
     *
     * @return
     * @throws Exception
     */
    public String delServer() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String DN = request.getParameter("DN");
        String json = null;
        String msg = null;
        boolean flag = x509ServerService.delete(DN);
        //得到liunx路径
        String realDirectory = DirectoryUtils.getDNDirectory(DN);
        //得到子CA在liunx下的路径
        String storeDirectory = DirectoryUtils.getSuperStoreDirectory(realDirectory);
        //获取CN
        String CN = DirectoryUtils.getCNForDN(DN);
        if (flag) {
            //删除用户文件
            DirectoryUtils.delStoreFiles(CN, storeDirectory);
            msg = "注销设备成功,通用名:" + CN;
            json = "{success:true,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
        } else {
            msg = "注销设备失败,删除信息失败,通用名:" + CN;
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }


    public String revokeServer() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        //得到上级DN
        String superDN = DirectoryUtils.getDNSuper(DN);
        //得到liunx路径
        String selfDirectory = DirectoryUtils.getDNDirectory(DN);
        //得到父CA名称
        String superCn = DirectoryUtils.getCNSuper(superDN);
        //得到子CA在liunx下的路径
        String storeDirectory = DirectoryUtils.getSuperStoreDirectory(selfDirectory);
        //得到父CA在liunx下的路径
        String superStoreDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
        //吊销证书
        boolean flag = X509ShellUtils.build_revoke(storeDirectory + "/" + CN + X509Context.certName, superStoreDirectory + "/" + superCn + X509Context.keyName, superStoreDirectory + "/" + superCn + X509Context.certName, storeDirectory + "/" + superCn + X509Context.config_type_ca);
        if (flag) {
            ModificationItem modificationItem[] = new ModificationItem[1];
            modificationItem[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509Server.getCertStatusAttr(), "1"));
            try {
                context.modifyAttributes(DN, modificationItem);
                msg = "吊销证书成功,通用名:" + CN;
                json = "{success:true,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
                boolean crl_flag = AutoCRL.CRL();
                if (crl_flag) {
                    logger.info("吊销列表文件生成成功,生成时间:" + new Date());
                } else {
                    logger.info("吊销列表文件生成失败,失败时间:" + new Date());
                }
            } catch (Exception e) {
                msg = "吊销证书失败,保存吊销信息出错,通用名:" + CN;
                json = "{success:false,msg:'" + msg + "'}";
                logger.error(e.getMessage(), e);
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
            } finally {
                ldapUtils.close(context);
            }
        } else {
            msg = "吊销证书失败,执行吊销时出现错误,通用名:" + CN;
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备证书", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String downCertificate() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";

        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String subPath = null;
        String subPfxPath = null;
        subPfxPath = dir + CN + X509Context.pkcsName;
        subPath = dir + CN + X509Context.certName;
        //得到父路径
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        //得到用户的浏览器名  MSIE  Firefox
        String userBrowser = st.nextToken();
        File file = new File(subPfxPath);
        if (file.exists()) {
            FileUtil.downType(response, CN + X509Context.pkcsName, userBrowser);
            response = FileUtil.copy(file, response);
        } else {
            file = new File(subPath);
            if (file.exists()) {
                FileUtil.downType(response, CN + X509Context.certName, userBrowser);
                response = FileUtil.copy(file, response);
            }
        }
        json = "{success:true}";
        actionBase.actionEnd(response, json, result);
        return null;
    }


    /**
     * 查询
     *
     * @return
     * @throws Exception
     */
    public String findServer() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        LdapUtils ldapUtils = new LdapUtils();
        DirContext ctx = ldapUtils.getCtx();
        StringBuilder json = new StringBuilder("");
        int first = Integer.parseInt(request.getParameter("start"));
        int end = Integer.parseInt(request.getParameter("limit"));
        String cn = request.getParameter("cn");
        String serverIp = request.getParameter("serverIp");
        String desc = request.getParameter("desc");
        String province = request.getParameter("province");
        String city = request.getParameter("city");
        String organization = request.getParameter("organization");
        String institutions = request.getParameter("institutions");
        //得到过滤条件
        StringBuilder stringBuilder = getFilterServer(cn, serverIp, desc, province, city, organization, institutions);
        //得到查寻所有数据
        List<SearchResult> resultList = getAllResultList(ctx, stringBuilder);
        //得到返回分页list
        List<String> list = getReturnList(resultList);
        //返回
        StringBuffer showData = getReturnData(first, end, list);

        json.append("{totalCount:" + resultList.size() + ",root:[" + showData.toString() + "]}");
        ldapUtils.close(ctx);
        actionBase.actionEnd(response, json.toString(), result);
        return null;
    }

    /**
     * 获取返回结果集
     *
     * @param first
     * @param limitInt
     * @param list
     * @return
     */
    private StringBuffer getReturnData(Integer first, Integer limitInt, List<String> list) {
        StringBuffer showData = new StringBuffer();
        int end = first + limitInt;
        int index = end > list.size() ? list.size() : end;
        for (int i = first; i < index; i++) {
            showData.append(list.get(i));
            if (i != index - 1) {
                showData.append(",");
            }
        }
        return showData;
    }

    /**
     * 查询所有记录
     *
     * @param context
     * @param stringBuilder
     * @return
     * @throws javax.naming.NamingException
     */
    private List<SearchResult> getAllResultList(DirContext context, StringBuilder stringBuilder) throws NamingException {
        List<SearchResult> resultList = new ArrayList<>();
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration results = context.search(LdapXMLUtils.getValue(LdapXMLUtils.base), stringBuilder.toString(), sc);
        while (results.hasMore()) {
            SearchResult sr = (SearchResult) results.next();
            resultList.add(sr);
        }
        return resultList;
    }

    /**
     * 分页返回list
     *
     * @param resultList
     * @return
     * @throws NamingException
     */
    private List<String> getReturnList(List<SearchResult> resultList) throws NamingException {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < resultList.size(); i++) {
            SearchResult sr = resultList.get(i);
            //获取终端设备条目数据
            String json = X509ServerAttrJsonMapper.mapJsonFromAttr(sr);
            list.add(json);
        }
        return list;
    }


    /**
     * @param cn           证书名称
     * @param serverIp     服务器IP
     * @param desc         描述
     * @param province     省份
     * @param city         市区
     * @param organization 组织
     * @param institutions 机构
     * @return
     */
    private StringBuilder getFilterServer(String cn, String serverIp, String desc, String province, String city, String organization, String institutions) {
        StringBuilder stringBuilder = new StringBuilder("(&(objectClass=" + X509Server.getObjAttr() + ")");
        if (cn != null && !cn.equals("")) {
            stringBuilder.append("(" + X509Server.getCnAttr() + "=*" + cn + "*)");
        }
        if (serverIp != null && !serverIp.equals("")) {
            stringBuilder.append("(" + X509Server.getServerIpAttr() + "=*" + serverIp + "*)");
        }
        if (desc != null && !desc.equals("")) {
            stringBuilder.append("(" + X509Server.getDescAttr() + "=*" + desc + "*)");
        }
        if (province != null && !province.equals("")) {
            stringBuilder.append("(" + X509Server.getProvinceAttr() + "=*" + province + "*)");
        }
        if (city != null && !city.equals("")) {
            stringBuilder.append("(" + X509Server.getCityAttr() + "=*" + city + "*)");
        }
        if (organization != null && !organization.equals("")) {
            stringBuilder.append("(" + X509Server.getOrganizationAttr() + "=*" + organization + "*)");
        }
        if (institutions != null && !institutions.equals("")) {
            stringBuilder.append("(" + X509Server.getInstitutionAttr() + "=*" + institutions + "*)");
        }
        stringBuilder.append(")");
        return stringBuilder;
    }

}
