package com.hzih.ca.web.action.client;

import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.X509User;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.entity.mapper.X509UserAttributeMapper;
import com.hzih.ca.entity.mapper.json.X509UserAttrJsonMapper;
import com.hzih.ca.service.LogService;
import com.hzih.ca.service.X509UserService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.crl.AutoCRL;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;
import com.hzih.ca.web.action.lisence.LicenseXML;
import com.hzih.ca.web.utils.*;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-6-30
 * Time: 下午3:10
 * To change this template use File | Settings | File Templates.
 */
public class X509UserAction extends ActionSupport {
    private Logger logger = Logger.getLogger(X509UserAction.class);
    private X509User x509User;
    private X509UserService x509UserService;

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

    public X509User getX509User() {
        return x509User;
    }

    public void setX509User(X509User x509User) {
        this.x509User = x509User;
    }


    public X509UserService getX509UserService() {
        return x509UserService;
    }

    public void setX509UserService(X509UserService x509UserService) {
        this.x509UserService = x509UserService;
    }

    /**
     * 更新设备信息
     *
     * @return
     * @throws Exception
     */
    public String modifyUserSmartCard() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        String CN = request.getParameter("CN");
        String DN = request.getParameter("DN");
        String json = "{success:false}";
        PrintWriter writer = response.getWriter();
        String type = request.getParameter("type");
        String dn = null;
        if (DN != null && !"".equals(DN)) {
            dn = DN;
        } else {
            dn = X509User.getCnAttr() + "=" + CN + "," + X509CaXML.getSignDn();
        }
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        ModificationItem modificationItem[] = new ModificationItem[1];
        modificationItem[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getDescAttr(), type));
        try {
            context.modifyAttributes(dn, modificationItem);
            json = "{success:true,dn:'" + dn + "'}";
        } catch (NamingException e) {
            logger.error(e.getMessage(), e);
        }
        writer.write(json);
        writer.close();
        return null;
    }

    public String downloadUserPfxFile() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String subPath = null;
        subPath = dir + CN + X509Context.pkcsName;
        File file = new File(subPath);
        if (file.exists()) {
            response = FileUtil.copy(file, response);
        }
        return null;
    }

    public String downloadUserCerFile() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String subPath = null;
        subPath = dir + CN + X509Context.certName;
        File file = new File(subPath);
        if (file.exists()) {
            response = FileUtil.copy(file, response);
        }
        return null;
    }

    public String downloadUserKeyFile() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String subPath = null;
        subPath = dir + CN + X509Context.keyName;
        File file = new File(subPath);
        if (file.exists()) {
            response = FileUtil.copy(file, response);
        }
        return null;
    }

    public String getUserPfxDownLoadURL() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        StringBuilder json = new StringBuilder();
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        json.append("http://")
                .append(LdapXMLUtils.getValue(LdapXMLUtils.host))
               /* .append(":")
                .append(LdapXMLUtils.getValue(LdapXMLUtils.port))*/
                .append("/X509UserAction_downloadUserPfxFile.action?DN=")
                .append(URLEncoder.encode(DN, "UTF-8"))
                .append("&CN=")
                .append(URLEncoder.encode(CN, "UTF-8"));
        writer.write("{success:true,url:'" + json.toString() + "',cn:'" + CN + "'}");
        writer.close();
        return null;
    }

    public String getUserCerDownLoadURL() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        StringBuilder json = new StringBuilder();
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        json.append("http://")
                .append(LdapXMLUtils.getValue(LdapXMLUtils.host))
            /*    .append(":")
                .append(LdapXMLUtils.getValue(LdapXMLUtils.port))*/
                .append("/X509UserAction_downloadUserCerFile.action?DN=")
                .append(URLEncoder.encode(DN, "UTF-8"))
                .append("&CN=")
                .append(URLEncoder.encode(CN, "UTF-8"));
        writer.write("{success:true,url:'" + json.toString() + "',cn:'" + CN + "'}");
        writer.close();
        return null;
    }

    public String getUserKeyDownLoadURL() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        StringBuilder json = new StringBuilder();
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到父路径
        json.append("http://")
                .append(LdapXMLUtils.getValue(LdapXMLUtils.host))
            /*    .append(":")
                .append(LdapXMLUtils.getValue(LdapXMLUtils.port))*/
                .append("/X509UserAction_downloadUserKeyFile.action?DN=")
                .append(URLEncoder.encode(DN, "UTF-8"))
                .append("&CN=")
                .append(URLEncoder.encode(CN, "UTF-8"));
        writer.write("{success:true,url:'" + json.toString() + "',cn:'" + CN + "'}");
        writer.close();
        return null;
    }

    /**
     * 校验用户名是否存在数据库
     *
     * @return
     * @throws Exception
     */
    public String existUser() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String cn = request.getParameter("cn");
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        String json = null;
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        NamingEnumeration results = context.search(X509CaXML.getSignDn(), X509User.getCnAttr() + "=" + cn, sc);
        if (results.hasMore()) {
            json = "{success:true,msg:'false'}";
        } else {
            json = "{success:true,msg:'true'}";
        }
        LdapUtils.close(context);
        actionBase.actionEnd(response, json, result);
        return null;
    }


    /**
     * 根据条件查找用户
     *
     * @return
     * @throws Exception
     */
    public String findUser() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        StringBuilder json = new StringBuilder("");
        String start = request.getParameter("start");
        String limit = request.getParameter("limit");
        Integer first = Integer.parseInt(start);
        Integer limitInt = Integer.parseInt(limit);
        String cn = request.getParameter("cn");
        String idCard = request.getParameter("idCard");
        String phone = request.getParameter("phone");
        String address = request.getParameter("address");
        String email = request.getParameter("email");
        String employeeCode = request.getParameter("employeeCode");
        String province = request.getParameter("province");
        String city = request.getParameter("city");
        String organization = request.getParameter("organization");
        String institutions = request.getParameter("institutions");

        StringBuilder stringBuilder = getFilterEndUser(cn, idCard, phone, address, email, employeeCode, province, city, organization, institutions);
//         得到查询结果列表
        List<SearchResult> resultList = getAllResultListData(context, stringBuilder);
//         得到返回结果列表
        List<String> list = getListData(resultList);


        StringBuffer showData = getReturnData(first, limitInt, list);

        json.append("{totalCount:" + resultList.size() + ",root:[" + showData.toString() + "]}");
        ldapUtils.close(context);
        actionBase.actionEnd(response, json.toString(), result);
        return null;
    }

    private List<SearchResult> getAllResultListData(DirContext context, StringBuilder stringBuilder) throws NamingException {
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

    private List<String> getListData(List<SearchResult> resultList) throws NamingException {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < resultList.size(); i++) {
            SearchResult sr = resultList.get(i);
            String data = X509UserAttrJsonMapper.mapJsonFromAttr(sr);
            list.add(data.toString());
        }
        return list;
    }

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

    private StringBuilder getFilterEndUser(String username, String id, String phone, String address, String email, String jobNumber, String province, String city, String organization, String institutions) {
        StringBuilder stringBuilder = new StringBuilder("(&(objectClass=" + X509User.getObjAttr() + ")");
        if (username != null && !username.equals("")) {
            stringBuilder.append("(" + X509User.getCnAttr() + "=*" + username + "*)");
        }
        if (id != null && !id.equals("")) {
            stringBuilder.append("(" + X509User.getIdCardAttr() + "=*" + id + "*)");
        }
        if (phone != null && !phone.equals("")) {
            stringBuilder.append("(" + X509User.getPhoneAttr() + "=*" + phone + "*)");
        }
        if (address != null && !address.equals("")) {
            stringBuilder.append("(" + X509User.getAddressAttr() + "=*" + address + "*)");
        }
        if (email != null && !email.equals("")) {
            stringBuilder.append("(" + X509User.getUserEmailAttr() + "=*" + email + "*)");
        }
        if (jobNumber != null && !jobNumber.equals("")) {
            stringBuilder.append("(" + X509User.getEmployeeCodeAttr() + "=*" + jobNumber + "*)");
        }
        if (province != null && !province.equals("")) {
            stringBuilder.append("(" + X509User.getOrgcodeAttr() + "=*" + province + "*)");
        }
        if (city != null && !city.equals("")) {
            stringBuilder.append("(" + X509User.getCityAttr() + "=*" + city + "*)");
        }
        if (organization != null && !organization.equals("")) {
            stringBuilder.append("(" + X509User.getOrganizationAttr() + "=*" + organization + "*)");
        }
        if (institutions != null && !institutions.equals("")) {
            stringBuilder.append("(" + X509User.getInstitutionAttr() + "=*" + institutions + "*)");
        }
        stringBuilder.append(")");
        return stringBuilder;
    }

    /**
     * 签发用户证书
     *
     * @return
     * @throws Exception
     */
    public String signX509User() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String msg = null;
        String json = null;
        //签发DN
        String signDn = X509CaXML.getSignDn();
        boolean flag = LicenseXML.readLicense(1);
        if (flag) {
            //数据DN
            String DN = DNUtils.add(signDn, x509User.getCn());
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
            flag = X509UserConfigUtils.buildUser(x509User, storeDirectory);
            if (flag) {
                //构建csr请求
                flag = X509ShellUtils.build_csr(x509Ca.getKeyLength(), storeDirectory + "/" + x509User.getCn() + X509Context.keyName, storeDirectory + "/" + x509User.getCn() + X509Context.csrName, storeDirectory + "/" + x509User.getCn() + X509Context.config_type_certificate);
                if (flag) {
                    //签发用户CA
                    flag = X509ShellUtils.build_sign_csr(storeDirectory + "/" + x509User.getCn() + X509Context.csrName, storeDirectory + "/" + signCn + X509Context.config_type_ca, X509Context.certificate_type_client, superStoreDirectory + "/" + signCn + X509Context.certName, superStoreDirectory + "/" + signCn + X509Context.keyName, storeDirectory + "/" + x509User.getCn() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                    if (flag) {
                        //构建pfx文件
                        flag = X509ShellUtils.build_pkcs12(storeDirectory + "/" + x509User.getCn() + X509Context.keyName, storeDirectory + "/" + x509User.getCn() + X509Context.certName, storeDirectory + "/" + x509User.getCn() + X509Context.pkcsName);
                        if (flag) {
//                            String key = FileHandles.readFileByLines(storeDirectory + "/" + x509User.getCn() + X509Context.keyName);
                            File cerFile = new File(storeDirectory + "/" + x509User.getCn() + X509Context.certName);
//                            String certificate = null;
//                            if (cerFile.exists())
//                                certificate = FileHandles.readFileByLines(cerFile);
                            CertificateUtils certificateUtils = new CertificateUtils();
                            X509Certificate cert = certificateUtils.get_x509_certificate(cerFile);
                            x509User.setCertStatus("0");
                            x509User.setIssueCa(signDn);
//                            x509User.setKey(key);
//                            x509User.setCertBase64Code(certificate);
                            x509User.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                            x509User.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                            x509User.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                            //
                            x509User.setUserCertificateAttr(cert.getEncoded());
                            boolean save_flag = x509UserService.add(x509User);
                            if (save_flag) {
                                LicenseXML.addLicense(1);
                                msg = "签发用户证书成功,用户名" + x509User.getCn();
                                json = "{success:true,msg:'" + msg + "'}";
                                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                            } else {
                                msg = "签发用户证书失败,保存到LDAP数据库失败,用户名" + x509User.getCn();
                                json = "{success:false,msg:'" + msg + "'}";
                                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                            }
                        }else {
                            msg = "签发用户证书失败,构建PKCS文件出现错误!用户名" + x509User.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                        }
                    } else {
                        msg = "签发用户证书失败,签发时出现错误!用户名" + x509User.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                    }
                } else {
                    msg = "签发用户证书失败,构建用户信息时出现错误,请确定用户信息填写正确,且未包含特殊字符!用户名" + x509User.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                }
            } else {
                msg = "签发用户证书失败,构建用户信息时出现错误,请确定用户信息正确填写!用户名" + x509User.getCn();
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
            }
        } else {
            msg = "license名额已达上限,无法签发证书";
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 更新用户证书
     *
     * @return
     * @throws Exception
     */
    public String modifyUser() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        //签发路径
        String signDn = X509CaXML.getSignDn();
        //结点路径
        String DN = request.getParameter("DN");
        //DN对应绝对路径
        String realDirectory = DirectoryUtils.getDNDirectory(DN);
        //得到父CA名称
        String signCn = DirectoryUtils.getCNSuper(signDn);
        //得到子CA在liunx下的路径
        String storeDirectory = DirectoryUtils.getSuperStoreDirectory(realDirectory);
        //得到父CA在liunx下的路径
        String superStoreDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
        //得到父ca结果集
        SearchResult fatherResults = LdapUtils.findSuperNode(DN);
        //根据结果集获取x509ca对象
        X509Ca x509Ca = X509CaAttributeMapper.mapFromAttributes(fatherResults);
        //构建用户请求文件
        boolean flag = X509UserConfigUtils.buildUser(x509User, storeDirectory);
        if(flag) {
            flag = X509ShellUtils.build_csr(x509Ca.getKeyLength(), storeDirectory + "/" + x509User.getCn() + X509Context.keyName, storeDirectory + "/" + x509User.getCn() + X509Context.csrName, storeDirectory + "/" + x509User.getCn() + X509Context.config_type_certificate);
            if (flag) {
                //构建csr请求
                flag = X509ShellUtils.build_sign_csr(storeDirectory + "/" + x509User.getCn() + X509Context.csrName, storeDirectory + "/" + signCn + X509Context.config_type_ca, X509Context.certificate_type_client, superStoreDirectory + "/" + signCn + X509Context.certName, superStoreDirectory + "/" + signCn + X509Context.keyName, storeDirectory + "/" + x509User.getCn() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                if (flag) {
                    //构建pfx文件
                    flag = X509ShellUtils.build_pkcs12(storeDirectory + "/" + x509User.getCn() + X509Context.keyName, storeDirectory + "/" + x509User.getCn() + X509Context.certName, storeDirectory + "/" + x509User.getCn() + X509Context.pkcsName);
                    if (flag) {
//                        String key = FileHandles.readFileByLines(storeDirectory + "/" + x509User.getCn() + X509Context.keyName);
                        File cerFile = new File(storeDirectory + "/" + x509User.getCn() + X509Context.certName);
//                        String certificate = null;
//                        if (cerFile.exists())
//                            certificate = FileHandles.readFileByLines(cerFile);
                        CertificateUtils certificateUtils = new CertificateUtils();
                        X509Certificate cert = certificateUtils.get_x509_certificate(cerFile);
                        x509User.setCertStatus("0");
                        x509User.setIssueCa(signDn);
                        x509User.setDn(DN);
//                        x509User.setKey(key);
//                        x509User.setCertBase64Code(certificate);
                        x509User.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                        x509User.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                        x509User.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                        //
                        x509User.setUserCertificateAttr(cert.getEncoded());
                        boolean modify_flag = x509UserService.modify(x509User);
                        if (modify_flag) {
                            msg = "更新用户证书成功!用户名:" + x509User.getCn();
                            json = "{success:true,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                        } else {
                            msg = "更新用户证书失败!用户名:" + x509User.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                        }
                    } else {
                        msg = "更新用户证书失败!构建PKCS文件出错,用户名:" + x509User.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                    }
                } else {
                    msg = "更新用户证书失败!请确定用户信息是否正确填写,用户名:" + x509User.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                }
            } else {
                msg = "构建用户请求文件出错!请确定用户信息是否正确填写,用户名:" + x509User.getCn();
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
            }
        }  else {
            msg = "构建用户信息出错!请确定用户信息是否正确填写,用户名:" + x509User.getCn();
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String delUser() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String DN = request.getParameter("DN");
        String json = null;
        String msg = null;
        //得到liunx路径
        String realDirectory = DirectoryUtils.getDNDirectory(DN);
        //得到子CA在liunx下的路径
        String storeDirectory = DirectoryUtils.getSuperStoreDirectory(realDirectory);
        //获取CN
        String CN = DirectoryUtils.getCNForDN(DN);
        try {
            boolean flag = x509UserService.delete(DN);
            if (flag) {
                //删除用户文件
                DirectoryUtils.delStoreFiles(CN, storeDirectory);
                msg = "注销用户成功!用户名:" + CN;
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                json = "{success:true,msg:'" + msg + "'}";
            } else {
                msg = "注销用户失败,删除用户信息出错,用户名:" + CN;
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                json = "{success:false,msg:'" + msg + "'}";
            }
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
            msg = "注销用户失败,删除用户信息出错,用户名:" + CN;
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            json = "{success:false,msg:'" + msg + "'}";
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String revokeUser() throws Exception {
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
            modificationItem[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getCertStatusAttr(), "1"));
            try {
                context.modifyAttributes(DN, modificationItem);
                msg = "吊销证书成功!用户名:" + CN;
                json = "{success:true,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                boolean crl_flag = AutoCRL.CRL();
                if (crl_flag) {
                    logger.info("吊销列表文件生成成功,生成时间:" + new Date());
                } else {
                    logger.info("吊销列表文件生成失败,生成失败时间:" + new Date());
                }
            } catch (Exception e) {
                msg = "吊销证书失败!用户名:" + CN;
                logger.error(e.getMessage(),e);
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            } finally {
                ldapUtils.close(context);
            }
        } else {
            msg = "吊销证书失败!用户名:" + CN;
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String retryUser() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到上级DN
        String superDn = DirectoryUtils.getDNSuper(DN);
        //得到liunx路径
        String realDirectory = DirectoryUtils.getDNDirectory(DN);
        String cnSuper = DirectoryUtils.getCNSuper(superDn);
        //得到子CA在liunx下的路径
        String storeDirectory = DirectoryUtils.getSuperStoreDirectory(realDirectory);
        //得到父CA在liunx下的路径
        String superStoreDirectory = DirectoryUtils.getSuperStoreDirectory(storeDirectory);
        //得到父ca结果集
        SearchResult fatherResults = LdapUtils.findCurrentNode(DN);
        //获取上组签发CA
        X509User u = X509UserAttributeMapper.mapFromAttributes(fatherResults);
        //构建服务器请求文件
        boolean flag = X509UserConfigUtils.buildUser(u, storeDirectory);
        if (flag) {
            flag = X509ShellUtils.build_again_csr(storeDirectory + "/" + CN + X509Context.keyName, storeDirectory + "/" + CN + X509Context.csrName, storeDirectory + "/" + CN + X509Context.config_type_certificate);
            if (flag) {
                flag = X509ShellUtils.build_sign_csr(storeDirectory + "/" + u.getCn() + X509Context.csrName, storeDirectory + "/" + cnSuper + X509Context.config_type_ca, X509Context.certificate_type_client, superStoreDirectory + "/" + cnSuper + X509Context.certName, superStoreDirectory + "/" + cnSuper + X509Context.keyName, storeDirectory + "/" + u.getCn() + X509Context.certName, String.valueOf(X509Context.default_certificate_validity));
                if (flag) {
                    flag = X509ShellUtils.build_pkcs12(storeDirectory + "/" + u.getCn() + X509Context.keyName, storeDirectory + "/" + u.getCn() + X509Context.certName, storeDirectory + "/" + u.getCn() + X509Context.pkcsName);
                    if (flag) {
//                        String key = FileHandles.readFileByLines(storeDirectory + "/" + u.getCn() + X509Context.keyName);
                        File cerFile = new File(storeDirectory + "/" + u.getCn() + X509Context.certName);
//                        String certificate = null;
//                        if (cerFile.exists())
//                            certificate = FileHandles.readFileByLines(cerFile);
                        CertificateUtils certificateUtils = new CertificateUtils();
                        X509Certificate cert = certificateUtils.get_x509_certificate(cerFile);
                        u.setCertStatus("0");
                        u.setIssueCa(superDn);
                        u.setDn(DN);
//                        u.setKey(key);
//                        u.setCertBase64Code(certificate);
                        u.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                        u.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                        u.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                        //
                        u.setUserCertificateAttr(cert.getEncoded());
                        boolean modify_flag = x509UserService.modify(u);
                        if (modify_flag) {
                            msg = "重发用户证书成功,用户名" + u.getCn();
                            json = "{success:true,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                        } else {
                            msg = "重发用户证书失败,保存到LDAP数据库出错,用户名" + u.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                        }
                    } else {
                        msg = "重发用户证书失败,构建PKCS文件出错,用户名" + u.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                    }
                }else {
                    msg = "重发用户证书失败,签发证书出错,用户名" + u.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
                }
            }else {
                msg = "重发用户证书失败,请确定用户信息是否正确填写且未包含特殊字符,用户名" + u.getCn();
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
            }
        }else {
            msg = "重发用户证书失败,请确定用户信息是否正确填写,用户名" + u.getCn();
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户证书", msg);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

}
