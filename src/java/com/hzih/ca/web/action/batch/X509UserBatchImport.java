package com.hzih.ca.web.action.batch;

import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.X509User;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.service.LogService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.StringContext;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;
import com.hzih.ca.web.action.lisence.LicenseXML;
import com.hzih.ca.web.utils.*;
import com.opensymphony.xwork2.ActionSupport;
import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;
import jxl.write.WriteException;
import org.apache.log4j.Logger;
import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.struts2.ServletActionContext;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 12-8-3
 * Time: 上午11:41
 * To change this template use File | Settings | File Templates.
 */
public class X509UserBatchImport extends ActionSupport {
    private List<X509User> x509UserList = null;
    private File uploadFile;
    private String uploadFileFileName;
    private String uploadFileContentType;
    private LdapUtils ldapUtils = new LdapUtils();
    private Logger logger = Logger.getLogger(X509UserBatchImport.class);
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

    /**
     * 下载批量导入用户模板文件
     *
     * @return
     * @throws Exception
     */
    public String downloadModel() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        /*得到用户的浏览器名  MS IE  Firefox*/
        String userBrowser = st.nextToken();
        File file = new File(StringContext.systemPath + "/model/ImportUsers.xls");
        if (file.exists()) {
            FileUtil.downType(response, file.getName(), userBrowser);
            response = FileUtil.copy(file, response);
            json = "{success:true}";
        } else {
            logger.info("下载批量导入用户模板文件失败，文件不存在!");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String downloadExportUser() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent, ";");
        st.nextToken();
        /*得到用户的浏览器名  MS IE  Firefox*/
        String userBrowser = st.nextToken();
        File file = new File(StringContext.systemPath + "/model/ExportUser.xls");
        if (file.exists()) {
            FileUtil.downType(response, file.getName(), userBrowser);
            response = FileUtil.copy(file, response);
            json = "{success:true}";
            logger.info("下载用户Excel数据成功！");
        } else {
            logger.info("下载用户Excel数据失败，文件不存在！");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String batchFlag() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = "{success:false}";
        String msg = null;
        if (!uploadFileFileName.endsWith(".xls") && !uploadFileFileName.endsWith(".et")) {
            msg = "导入的文件不是[.xls]或者[.et]文件";
            json = "{success:false,msg:'" + msg + "'}";
        }
        if (msg == null) {
            HSSFWorkbook workbook = null;
            try {
                workbook = new HSSFWorkbook(new POIFSFileSystem(new FileInputStream(uploadFile)));
            } catch (IOException e) {
                msg = "没有找到导入文件";
                json = "{success:false,msg:'" + msg + "'}";
                logger.info("没有找到导入文件::" + e.getMessage(),e);
            }
            if (workbook != null) {
                HSSFSheet sheet = workbook.getSheetAt(0);
                int lastRowNum = sheet.getLastRowNum();
                DirContext context = ldapUtils.getCtx();
                try {
                    StringBuilder readMsg = new StringBuilder();
                    List<X509User> x509Users = findCount(readMsg, sheet, lastRowNum);
                    if (x509Users == null) {
                        json = "{success:false,msg:'" + readMsg.toString() + "'}";
                    } else {
                        String modify_msg = null;
                        SearchControls constraints = new SearchControls();
                        constraints.setSearchScope(SearchControls.OBJECT_SCOPE);
                        this.x509UserList = x509Users;
                        for (X509User user : x509Users) {
//                            String Dn = X509User.getCnAttr() + "=" + user.getCn() + "_" + user.getIdCard() + "," + X509CaXML.getSignDn();
                            NamingEnumeration en = null;
                            try {
                                en = context.search(user.getDn(), X509User.getCnAttr() + "=*", constraints);
                                if (en.hasMore()) {
                                    modify_msg = "Excel文件中某些用户已在在LDAP数据库,是否更新?";
                                    if (modify_msg != null)
                                        readMsg.append(modify_msg).append("\\n");
                                    break;
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                //
                            }
                        }
                        if (modify_msg != null) {
                            json = "{success:true,msg:'" + readMsg + "'}";
                        } else {
                            msg = "Excel文件中没有任何用户存在LDAP数据库,是否添加?";
                            readMsg.append(msg).append("\\n");
                            json = "{success:true,msg:'" + readMsg + "'}";
                        }
                    }
                } catch (Exception e) {
                    logger.error(e.getMessage(),e);
                    logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "ImportUser", "出错!" + msg);
                } finally {
                    LdapUtils.close(context);
                }
            }
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String batchImportUser() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String flag = request.getParameter("flag");
        String json = "{success:false}";
        String msg = null;
        DirContext context = ldapUtils.getCtx();
        try {
//            StringBuilder readMsg = new StringBuilder();
            List<X509User> x509UserLists = this.x509UserList; //findCount(readMsg, sheet, lastRowNum);
            if (x509UserLists == null) {
                json = "{success:false,msg:'未读取到任何用户,不能进行操作!'}";
            } else {
                SearchControls constraints = new SearchControls();
                constraints.setSearchScope(SearchControls.OBJECT_SCOPE);
//                boolean modify_flag = false;
                for (X509User user : x509UserLists) {
//                    String Dn = X509User.getCnAttr() + "=" + user.getCn() + "_" + user.getIdCard() + "," + X509CaXML.getSignDn();
                    NamingEnumeration en = null;
                    try {
                        en = context.search(user.getDn(), X509User.getCnAttr() + "=*", constraints);
                        if (en.hasMore()) {
                            if (flag.equals("true"))
                                sign_user(SessionUtils.getAccount(request).getUserName(), context, user, true);
                        } else {
                            sign_user(SessionUtils.getAccount(request).getUserName(), context, user, false);
                        }
                    } catch (Exception e) {
                        logger.error(e.getMessage(),e);
                        sign_user(SessionUtils.getAccount(request).getUserName(), context, user, false);
                    }
                }
                this.x509UserList = null;
                msg = "批量导入用户完成";
                json = "{success:true,msg:'" + msg + "'}";
                logger.info("批量导入用户完成");
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "ImportUser", "导入用户!");
            }
        } catch (Exception e) {
            msg = "批量导入用户失败::" + msg;
            json = "{success:false,msg:'" + msg + "'}";
            logger.info("批量导入用户失败::" + msg,e);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "ImportUser", "导入用户失败!" + msg);
        } finally {
            LdapUtils.close(context);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String batchExportUser() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        HttpServletRequest request = ServletActionContext.getRequest();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        DirContext context = ldapUtils.getCtx();
        String msg = null;
        String json = null;
        try {
            String file = StringContext.systemPath+"/model/ExportUser.xls";
            boolean flag = load(file,context);
            if(flag){
                msg = "导出用户数据到服务器完成"+new Date();
                json = "{success:true,flag:true,msg:'" + msg + "'}";
                logger.info("导出用户数据到服务器完成"+new Date());
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "ExportUser", "导出用户!");
            }else {
                msg = "导出用户数据到服务器失败"+new Date();
                json = "{success:false,flag:false,msg:'" + msg + "'}";
                logger.info("导出用户数据到服务器失败"+new Date());
                logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "ExportUser", "导出用户!");
            }
        }catch (Exception e){
            msg = "导出用户数据到服务器失败"+new Date();
            json = "{success:false,flag:false,msg:'" + msg + "'}";
            logger.info("导出用户数据到服务器失败"+new Date());
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "ExportUser", "导出用户!");
        }finally {
            LdapUtils.close(context);
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    private String getCellValue(HSSFCell aCell) {
        if (aCell.getCellType() == HSSFCell.CELL_TYPE_NUMERIC) {// 数字
            return String.valueOf(aCell.getNumericCellValue());
        } else if (aCell.getCellType() == HSSFCell.CELL_TYPE_BOOLEAN) {// Boolean
            return String.valueOf(aCell.getBooleanCellValue());
        } else if (aCell.getCellType() == HSSFCell.CELL_TYPE_STRING) {// 字符串
            return aCell.getStringCellValue();
        } else if (aCell.getCellType() == HSSFCell.CELL_TYPE_FORMULA) {// 公式
            return String.valueOf(aCell.getCellFormula());
        } else if (aCell.getCellType() == HSSFCell.CELL_TYPE_BLANK) {// 空值
            return null;
        } else if (aCell.getCellType() == HSSFCell.CELL_TYPE_ERROR) {// 故障
            return null;
        } else {
            //未知类型
            return null;
        }
    }

    private List<X509User> findCount(StringBuilder readMsg, HSSFSheet sheet, int lastRowNum) throws NamingException {

        List<X509User> x509Users = new ArrayList<>();
        boolean isEmptyLine = false;
        for (int i = 1; i <= lastRowNum; i++) {
            HSSFRow row = sheet.getRow(i);
            if (row != null) {
                int cellNum = 0;

                String msg = null;
                String cn = null;
                String idCard = null;
                String province = null;
                String city = null;
                String organization = null;
                String institution = null;
                String phone = null;
                String address = null;
                String userEmail = null;
                String employeeCode = null;

                HSSFCell cell = row.getCell(cellNum++);

                boolean isNeedToAddMany = true;
                //cn

                if (cell != null) {
                    cn = getCellValue(cell);
                    if (cn == null || "".equals(cn)) {
                        isNeedToAddMany = false;
                    }
                }

                //idCard
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    idCard = getCellValue(cell);
                    if (idCard == null || "".equals(idCard)) {
                        isNeedToAddMany = false;
                    } else if (idCard.length() < 15) {
                        isNeedToAddMany = false;
                    } else {
                        if (idCard.length() > 18) {
                            isNeedToAddMany = false;
                        }
                    }
                }
                //province
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    province = getCellValue(cell);
                    if (province == null || "".equals(province)) {
                        isNeedToAddMany = false;
                    }
                }
                //city
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    city = getCellValue(cell);
                    if (city == null || "".equals(city)) {
                        isNeedToAddMany = false;
                    }
                }

                //organization
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    organization = getCellValue(cell);
                    if (organization == null || "".equals(organization)) {
                        isNeedToAddMany = false;
                    }
                }

                //institution
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    institution = getCellValue(cell);
                    if (institution == null || "".equals(institution)) {
                        isNeedToAddMany = false;
                    }
                }

                //phone
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    phone = getCellValue(cell);
                    if (phone == null || "".equals(phone)) {
                        isNeedToAddMany = false;
                    }
                }

                //address
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    address = getCellValue(cell);
                    if (address == null || "".equals(address)) {
                        isNeedToAddMany = false;
                    }
                }

                //userEmail
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    userEmail = getCellValue(cell);
                    if (userEmail == null || "".equals(userEmail)) {
                        isNeedToAddMany = false;
                    }
                }

                //employeeCode
                cell = row.getCell(cellNum++);
                if (cell != null) {
                    employeeCode = getCellValue(cell);
                    if (employeeCode == null || "".equals(employeeCode)) {
                        isNeedToAddMany = false;
                    }
                }

                if ((employeeCode == null || "".equals(employeeCode))
                        && (userEmail == null || "".equals(userEmail))
                        && (address == null || "".equals(address))
                        && (phone == null || "".equals(phone))
                        && (province == null || "".equals(province))
                        && (city == null || "".equals(city))
                        && (organization == null || "".equals(organization))
                        && (institution == null || "".equals(institution))
                        && (idCard == null || "".equals(idCard))
                        && (cn == null || "".equals(cn))) {
                    isEmptyLine = true;
                }

                if (!isEmptyLine) {
                    if (!isNeedToAddMany) {
                        msg = "第" + (i + 1) + "行,用户信息不完整,忽略操作!";
                        readMsg.append(msg).append("\\n");
                    }
                }

                if (isNeedToAddMany && !isEmptyLine) {
                    X509User x509User = new X509User();
                    x509User.setCn(cn);
                    x509User.setIdCard(idCard);
                    x509User.setPhone(phone);
                    x509User.setAddress(address);
                    x509User.setUserEmail(userEmail);
                    x509User.setProvince(province);
                    x509User.setCity(city);
                    x509User.setOrganization(organization);
                    x509User.setInstitution(institution);
                    x509User.setEmployeeCode(employeeCode);
                    x509User.setIssueCa(X509CaXML.getSignDn());
                    StringBuilder dn = new StringBuilder(x509User.getCnAttr() + "=" + cn).append("," + x509User.getIssueCa());
                    x509User.setDn(dn.toString());
                    x509User.setCertStatus("0");
                    x509Users.add(x509User);
                    if (x509Users.size() > 1000) {
                        msg = "Excel文件有效数据内容大于1000行,单次只能导入1000行,导入失败!<br/>";
                        readMsg.append(msg).append("\\n");
                        logger.info(msg);
                        return null;
                    }
                }
            }
        }
        return x509Users;
    }

    private boolean modify_user(DirContext ctx, X509User x509User) {
        if (x509User == null || x509User.getDn() == null || x509User.getDn().length() <= 0) {
            return false;
        }
        List<ModificationItem> mList = new ArrayList<ModificationItem>();
        if (x509User.getIdCard() != null && x509User.getIdCard().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getIdCardAttr(), x509User.getIdCard())));
        if (x509User.getPhone() != null && x509User.getPhone().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getPhoneAttr(), x509User.getPhone())));
        if (x509User.getAddress() != null && x509User.getAddress().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getAddressAttr(), x509User.getAddress())));
        if (x509User.getUserEmail() != null && x509User.getUserEmail().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getUserEmailAttr(), x509User.getUserEmail())));
        if (x509User.getEmployeeCode() != null && x509User.getEmployeeCode().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(X509User.getEmployeeCodeAttr(), x509User.getEmployeeCode())));
        if (x509User.getOrgCode() != null && x509User.getOrgCode().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getOrgcodeAttr(), x509User.getOrgCode())));
        if (x509User.getPwd() != null && x509User.getPwd().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getPwdAttr(), x509User.getPwd())));
        if (x509User.getCertStatus() != null && x509User.getCertStatus().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getCertStatusAttr(), x509User.getCertStatus())));
        if (x509User.getSerial() != null && x509User.getSerial().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getSerialAttr(), x509User.getSerial())));
        if (x509User.getKey() != null && x509User.getKey().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getKeyAttr(), x509User.getKey())));
        if (x509User.getCreateDate() != null && x509User.getCreateDate().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getCreateDateAttr(), x509User.getCreateDate())));
        if (x509User.getEndDate() != null && x509User.getEndDate().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getEndDateAttr(), x509User.getEndDate())));
        if (x509User.getIssueCa() != null && x509User.getIssueCa().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getIssueCaAttr(), x509User.getIssueCa())));
        if (x509User.getCertType() != null && x509User.getCertType().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getCertTypeAttr(), x509User.getCertType())));
        if (x509User.getKeyLength() != null && x509User.getKeyLength().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getKeyLengthAttr(), x509User.getKeyLength())));
        if (x509User.getValidity() != null && x509User.getValidity().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getValidityAttr(), x509User.getValidity())));
        if (x509User.getProvince() != null && x509User.getProvince().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getProvinceAttr(), x509User.getProvince())));
        if (x509User.getCity() != null && x509User.getCity().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getCityAttr(), x509User.getCity())));
        if (x509User.getOrganization() != null && x509User.getOrganization().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getOrganizationAttr(), x509User.getOrganization())));
        if (x509User.getInstitution() != null && x509User.getInstitution().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getInstitutionAttr(), x509User.getInstitution())));
        if (x509User.getDesc() != null && x509User.getDesc().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getDescAttr(), x509User.getDesc())));
        if (x509User.getCertBase64Code() != null && x509User.getCertBase64Code().length() > 0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.getCertBase64CodeAttr(), x509User.getCertBase64Code())));
        if (x509User.getUserCertificateAttr() != null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(x509User.DEFAULT_userCertificateAttr, x509User.getUserCertificateAttr())));

        if (mList.size() > 0) {
            ModificationItem[] mArray = new ModificationItem[mList.size()];
            for (int i = 0; i < mList.size(); i++) {
                mArray[i] = mList.get(i);
            }
            try {
                ctx.modifyAttributes(x509User.getDn(), mArray);
                return true;
            } catch (Exception e) {
                logger.info("修改设备实体::" + x509User.getDn() + ":出现错误:" + e.getMessage(),e);
            }/* finally {
                LdapUtils.close(ctx);
            }*/
        }
        return false;
    }

    private boolean add_user(DirContext ctx, X509User x509User) {
        BasicAttribute ba = new BasicAttribute("objectclass");
        ba.add(X509User.getObjAttr()); //此处的x509User对应的是core.schema文件中的objectClass：x509User
        Attributes attr = new BasicAttributes();
        attr.put(ba);
        //必填属性，不能为null也不能为空字符串
        attr.put(x509User.getCnAttr(), x509User.getCn());
        //可选字段需要判断是否为空，如果为空则不能添加
        if (x509User.getIdCard() != null && x509User.getIdCard().length() > 0.) {
            attr.put(X509User.getIdCardAttr(), x509User.getIdCard());
        }
        if (x509User.getPhone() != null && x509User.getPhone().length() > 0.) {
            attr.put(X509User.getPhoneAttr(), x509User.getPhone());
        }
        if (x509User.getAddress() != null && x509User.getAddress().length() > 0.) {
            attr.put(X509User.getAddressAttr(), x509User.getAddress());
        }
        if (x509User.getUserEmail() != null && x509User.getUserEmail().length() > 0.) {
            attr.put(X509User.getUserEmailAttr(), x509User.getUserEmail());
        }
        if (x509User.getEmployeeCode() != null && x509User.getEmployeeCode().length() > 0.) {
            attr.put(X509User.getEmployeeCodeAttr(), x509User.getEmployeeCode());
        }
        if (x509User.getOrgCode() != null && x509User.getOrgCode().length() > 0) {
            attr.put(x509User.getOrgcodeAttr(), x509User.getOrgCode());
        }
        if (x509User.getPwd() != null && x509User.getPwd().length() > 0) {
            attr.put(x509User.getPwdAttr(), x509User.getPwd());
        }
        if (x509User.getCertStatus() != null && x509User.getCertStatus().length() > 0) {
            attr.put(x509User.getCertStatusAttr(), x509User.getCertStatus());
        }
        if (x509User.getSerial() != null && x509User.getSerial().length() > 0) {
            attr.put(x509User.getSerialAttr(), x509User.getSerial());
        }
        if (x509User.getKey() != null && x509User.getKey().length() > 0) {
            attr.put(x509User.getKeyAttr(), x509User.getKey());
        }
        if (x509User.getCreateDate() != null && x509User.getCreateDate().length() > 0) {
            attr.put(x509User.getCreateDateAttr(), x509User.getCreateDate());
        }
        if (x509User.getEndDate() != null && x509User.getEndDate().length() > 0) {
            attr.put(x509User.getEndDateAttr(), x509User.getEndDate());
        }
        if (x509User.getIssueCa() != null && x509User.getIssueCa().length() > 0) {
            attr.put(x509User.getIssueCaAttr(), x509User.getIssueCa());
        }
        if (x509User.getCertType() != null && x509User.getCertType().length() > 0) {
            attr.put(x509User.getCertTypeAttr(), x509User.getCertType());
        }
        if (x509User.getKeyLength() != null && x509User.getKeyLength().length() > 0) {
            attr.put(x509User.getKeyLengthAttr(), x509User.getKeyLength());
        }
        if (x509User.getValidity() != null && x509User.getValidity().length() > 0) {
            attr.put(x509User.getValidityAttr(), x509User.getValidity());
        }
        if (x509User.getProvince() != null && x509User.getProvince().length() > 0) {
            attr.put(x509User.getProvinceAttr(), x509User.getProvince());
        }
        if (x509User.getCity() != null && x509User.getCity().length() > 0) {
            attr.put(x509User.getCityAttr(), x509User.getCity());
        }
        if (x509User.getOrganization() != null && x509User.getOrganization().length() > 0) {
            attr.put(x509User.getOrganizationAttr(), x509User.getOrganization());
        }
        if (x509User.getInstitution() != null && x509User.getInstitution().length() > 0) {
            attr.put(x509User.getInstitutionAttr(), x509User.getInstitution());
        }
        if (x509User.getDesc() != null && x509User.getDesc().length() > 0) {
            attr.put(x509User.getDescAttr(), x509User.getDesc());
        }
        if (x509User.getCertBase64Code() != null && x509User.getCertBase64Code().length() > 0) {
            attr.put(x509User.getCertBase64CodeAttr(), x509User.getCertBase64Code());
        }
        if (x509User.getUserCertificateAttr() != null) {
            attr.put(x509User.DEFAULT_userCertificateAttr, x509User.getUserCertificateAttr());
        }
        StringBuilder dn = new StringBuilder(x509User.getCnAttr() + "=" + x509User.getCn()).append("," + x509User.getIssueCa());

        try {
            ctx.createSubcontext(dn.toString(), attr);
            return true;
        } catch (Exception e) {
            logger.info("新增用户实体::" + x509User.getDn() + ":出现错误:" + e.getMessage(),e);
        } /*finally {
            LdapUtils.close(ctx);
        }*/
        return false;
    }

    private boolean sign_user(String admin_, DirContext ctx, X509User x509User, boolean isUpdate) {
        String msg = null;
        //签发DN
        String signDn = X509CaXML.getSignDn();
        boolean flag = false;
        try {
            flag = LicenseXML.readLicense(1);
        } catch (Exception e) {
            e.printStackTrace();
        }
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
            X509Ca x509Ca = null;
            try {
                x509Ca = X509CaAttributeMapper.mapFromAttributes(fatherResults);
            } catch (NamingException e) {
                e.printStackTrace();
            }
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
                            String key = FileHandles.readFileByLines(storeDirectory + "/" + x509User.getCn() + X509Context.keyName);
                            File cerFile = new File(storeDirectory + "/" + x509User.getCn() + X509Context.certName);
                            String certificate = null;
                            if (cerFile.exists())
                                certificate = FileHandles.readFileByLines(cerFile);
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
                            try {
                                x509User.setUserCertificateAttr(cert.getEncoded());
                            } catch (CertificateEncodingException e) {
                                e.printStackTrace();
                            }
                            boolean save_flag = false;
                            if (isUpdate) {
                                save_flag = modify_user(ctx, x509User);
                            } else {
                                save_flag = add_user(ctx, x509User);
                            }
                            if (save_flag) {
                                try {
                                    LicenseXML.addLicense(1);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                msg = "批量签发证书成功,用户名" + x509User.getCn();
                                logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", admin_, "用户证书", msg);
                                return true;
                            } else {
                                msg = "批量签发用户证书失败,保存到LDAP数据库失败,用户名" + x509User.getCn();
                                logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                                logService.newLog("INFO", admin_, "用户证书", msg);
                                return false;
                            }
                        } else {
                            msg = "批量签发用户证书失败,构建PKCS文件出现错误!用户名" + x509User.getCn();
                            logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                            logService.newLog("INFO", admin_, "用户证书", msg);
                            return false;
                        }
                    } else {
                        msg = "批量签发用户证书失败,签发时出现错误!用户名" + x509User.getCn();
                        logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                        logService.newLog("INFO", admin_, "用户证书", msg);
                        return false;
                    }
                } else {
                    msg = "批量签发用户证书失败,构建用户信息时出现错误,请确定用户信息填写正确,且未包含特殊字符!用户名" + x509User.getCn();
                    logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                    logService.newLog("INFO", admin_, "用户证书", msg);
                    return false;
                }
            } else {
                msg = "批量签发用户证书失败,构建用户信息时出现错误,请确定用户信息正确填写!用户名" + x509User.getCn();
                logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
                logService.newLog("INFO", admin_, "用户证书", msg);
                return false;
            }
        } else {
            msg = "license名额已达上限,无法批量签发证书";
            logger.info("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + admin_ + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", admin_, "用户证书", msg);
            return false;
        }
    }

    private List<SearchResult> getAllResultListData(DirContext context) throws NamingException {
        List<SearchResult> resultList = new ArrayList<>();
        StringBuilder stringBuilder = new StringBuilder("(&(objectClass=" + X509User.getObjAttr() + ")");
        stringBuilder.append(")");
        String[] attrs = new String[]{
                "cn",
                "idCard",
                "phone",
                "address",
                "userEmail",
                "employeeCode",
                "province",
                "city",
                "organization",
                "institution"
        };
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setReturningAttributes(attrs);
        NamingEnumeration results = context.search(LdapXMLUtils.getValue(LdapXMLUtils.base), stringBuilder.toString(), sc);
        while (results.hasMore()) {
            SearchResult sr = (SearchResult) results.next();
            resultList.add(sr);
        }
        return resultList;
    }

    public boolean load(String file, DirContext context) throws IOException, WriteException {

        try {
            FileOutputStream output = new FileOutputStream(file);
            WritableWorkbook wk= Workbook.createWorkbook(output);
            // 创建工作表
            WritableSheet ws = wk.createSheet("用户信息", 0);
            //查询数据库中所有的数据
            List<SearchResult> list = getAllResultListData(context);
            //要插入到的Excel表格的行号，默认从0开始
            Label label_cn= new Label(0, 0, "用户名");//表示第
            Label label_idCard= new Label(1, 0, "身份证");
            Label label_phone= new Label(2, 0, "电话");
            Label label_address= new Label(3, 0, "地址");
            Label label_userEmail= new Label(4, 0, "邮件");
            Label label_employeeCode= new Label(5, 0, "警员编号");
            Label label_province = new Label(6, 0 , "省");
            Label label_city = new Label(7, 0 , "市");
            Label label_organization = new Label(8, 0 , "组织");
            Label label_institution = new Label(9, 0 , "机构");

            ws.addCell(label_cn);
            ws.addCell(label_idCard);
            ws.addCell(label_phone);
            ws.addCell(label_address);
            ws.addCell(label_userEmail);
            ws.addCell(label_employeeCode);
            ws.addCell(label_province);
            ws.addCell(label_city);
            ws.addCell(label_organization);
            ws.addCell(label_institution);

            for (int i = 0; i < list.size(); i++) {
                SearchResult result = list.get(i);
                Attributes attr = result.getAttributes();
                X509User x509User = new X509User();
                x509User.setCn((String) attr.get(X509User.getCnAttr()).get());
                if (attr.get(X509User.getIdCardAttr()) != null) {
                    x509User.setIdCard((String) attr.get(X509User.getIdCardAttr()).get());
                }
                if (attr.get(X509User.getPhoneAttr()) != null) {
                    x509User.setPhone((String) attr.get(X509User.getPhoneAttr()).get());
                }
                if (attr.get(X509User.getAddressAttr()) != null) {
                    x509User.setAddress((String) attr.get(X509User.getAddressAttr()).get());
                }
                if (attr.get(X509User.getUserEmailAttr()) != null) {
                    x509User.setUserEmail((String) attr.get(X509User.getUserEmailAttr()).get());
                }
                if (attr.get(X509User.getEmployeeCodeAttr()) != null) {
                    x509User.setEmployeeCode((String) attr.get(X509User.getEmployeeCodeAttr()).get());
                }
                if (attr.get(x509User.getProvinceAttr()) != null) {
                    x509User.setProvince((String)attr.get(x509User.getProvinceAttr()).get());
                }
                if (attr.get(x509User.getCityAttr()) != null) {
                    x509User.setCity((String)attr.get(x509User.getCityAttr()).get());
                }
                if (attr.get(x509User.getOrganizationAttr()) != null) {
                    x509User.setOrganization((String)attr.get(x509User.getOrganizationAttr()).get());
                }
                if (attr.get(x509User.getInstitutionAttr()) != null) {
                    x509User.setInstitution((String)attr.get(x509User.getInstitutionAttr()).get());
                }

                Label label_cn_i= new Label(0 , i+1,x509User.getCn());
                Label label_idCard_i= new Label(1, i+1, x509User.getIdCard());
                Label label_phone_i= new Label(2, i+1, x509User.getPhone());
                Label label_address_i= new Label(3, i+1,x509User.getAddress());
                Label label_userEmail_i= new Label(4, i+1, x509User.getUserEmail());
                Label label_employeeCode_i= new Label(5, i+1, x509User.getEmployeeCode());
                Label label_province_i= new Label(6, i+1, x509User.getProvince());
                Label label_city_i= new Label(7, i+1, x509User.getCity());
                Label label_organization_i= new Label(8, i+1, x509User.getOrganization());
                Label label_institution_i= new Label(9, i+1, x509User.getInstitution());

                ws.addCell(label_cn_i);
                ws.addCell(label_idCard_i);
                ws.addCell(label_phone_i);
                ws.addCell(label_address_i);
                ws.addCell(label_userEmail_i);
                ws.addCell(label_employeeCode_i);
                ws.addCell(label_province_i);
                ws.addCell(label_city_i);
                ws.addCell(label_organization_i);
                ws.addCell(label_institution_i);
            }
            //写进文档
            wk.write();
            // 关闭Excel工作簿对象
            wk.close();

            output.close();
            return true;
        } catch (NamingException e) {
            logger.error(e);
            return false;
        }
    }
}
