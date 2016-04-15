package com.hzih.ca.web.action.ca;


import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.X509User;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.service.X509UserService;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.utils.*;
import org.apache.log4j.Logger;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by Administrator on 14-7-24.
 */
public class ExternalUser extends HttpServlet {

    private static final String req_signCert = "0x000001";
    private static final String get_download_key = "0x000002";
    private static final String get_download_cert = "0x000003";
    private static final String get_status= "0x000004";

    private Logger logger = Logger.getLogger(ExternalUser.class);

    private X509UserService x509UserService;

    /**
     * <p>
     * 在Servlet中注入对象的步骤:
     * 1.取得ServletContext
     * 2.利用Spring的工具类WebApplicationContextUtils得到WebApplicationContext
     * 3.WebApplicationContext就是一个BeanFactory,其中就有一个getBean方法
     * 4.有了这个方法就可像平常一样为所欲为了,哈哈!
     * </p>
     */
    @Override
    public void init() throws ServletException {
        super.init();
        ServletContext servletContext = this.getServletContext();
        WebApplicationContext ctx = WebApplicationContextUtils.getWebApplicationContext(servletContext);
        x509UserService = (X509UserService) ctx.getBean("x509UserService");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setHeader("content-type", "text/html;charset=utf-8");
        String encode = request.getCharacterEncoding();
        System.out.print(encode);
        response.setCharacterEncoding("utf-8");
        String command = request.getParameter("command");
        String msg = null;
        String json = null;
        if(command!=null&&command.equals(get_status)){
            msg = "服务器可以正常连通";
            json = "{success:true,msg:'" + msg + "'}";
            PrintWriter writer = response.getWriter();
            writer.write(json);
            writer.flush();
            writer.close();
        }else if(command!=null&&command.length()>0&&command.equals(req_signCert)){
            String cn = request.getParameter("cn");
            String idCard = request.getParameter("idCard");
            String province = request.getParameter("province");
            String city = request.getParameter("city");
            String organization = request.getParameter("organization");
            String institution = request.getParameter("institution");
            String phone = request.getParameter("phone");
            String address = request.getParameter("address");
            String userEmail = request.getParameter("userEmail");
            if (cn != null && idCard != null && province != null && city != null && organization != null && institution != null && phone != null && address != null && userEmail != null) {
                X509User x509User = new X509User();
                x509User.setCn(cn);
                x509User.setIdCard(idCard);
                x509User.setProvince(province);
                x509User.setCity(city);
                x509User.setOrganization(organization);
                x509User.setInstitution(institution);
                x509User.setPhone(phone);
                x509User.setAddress(address);
                x509User.setUserEmail(userEmail);
                //签发DN
                String signDn = X509CaXML.getSignDn();
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
                    logger.error(e.getMessage(),e);
                }
                //构建用户请求文件
                boolean flag = X509UserConfigUtils.buildUser(x509User, storeDirectory);
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
//                                String key = FileHandles.readFileByLines(storeDirectory + "/" + x509User.getCn() + X509Context.keyName);
                                File cerFile = new File(storeDirectory + "/" + x509User.getCn() + X509Context.certName);
//                                String certificate = null;
//                                if (cerFile.exists())
//                                    certificate = FileHandles.readFileByLines(cerFile);
                                CertificateUtils certificateUtils = new CertificateUtils();
                                X509Certificate cert = certificateUtils.get_x509_certificate(cerFile);
                                x509User.setCertStatus("0");
                                x509User.setIssueCa(signDn);
//                                x509User.setKey(key);
//                                x509User.setCertBase64Code(certificate);
                                x509User.setCreateDate(String.valueOf(cert.getNotBefore().getTime()));
                                x509User.setEndDate(String.valueOf(cert.getNotAfter().getTime()));
                                x509User.setSerial(cert.getSerialNumber().toString(16).toUpperCase());
                                try {
                                    x509User.setUserCertificateAttr(cert.getEncoded());
                                } catch (CertificateEncodingException e) {
                                    logger.error(e.getMessage(),e);
                                }
                                String dn = DNUtils.add(signDn,x509User.getCn());
                                x509User.setDn(dn);
                                boolean save_flag = false;
                                try {
                                   boolean exist_flag =  x509UserService.exist(dn);
                                    if(exist_flag){
                                        save_flag = x509UserService.modify(x509User);
                                        if (save_flag) {
                                            msg = "更新用户证书成功,用户名:" + x509User.getCn();
                                            json = "{success:true,msg:'" + msg + "'}";
                                            logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                        }else {
                                            msg = "更新用户证书失败,保存到LDAP数据库失败,用户名:" + x509User.getCn();
                                            json = "{success:false,msg:'" + msg + "'}";
                                            logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                        }
                                    }else {
                                        save_flag = x509UserService.add(x509User);
                                        if (save_flag) {
                                            msg = "签发用户证书成功,用户名:" + x509User.getCn();
                                            json = "{success:true,msg:'" + msg + "'}";
                                            logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                        } else {
                                            msg = "签发用户证书失败,保存到LDAP数据库失败,用户名:" + x509User.getCn();
                                            json = "{success:false,msg:'" + msg + "'}";
                                            logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                        }
                                    }
                                } catch (Exception e) {
                                    logger.error(e.getMessage(),e);
                                }
                            } else {
                                msg = "签发用户证书失败,构建PKCS文件出现错误!用户名:" + x509User.getCn();
                                json = "{success:false,msg:'" + msg + "'}";
                                logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                            }
                        } else {
                            msg = "签发用户证书失败,签发时出现错误!用户名:" + x509User.getCn();
                            json = "{success:false,msg:'" + msg + "'}";
                            logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                        }
                    } else {
                        msg = "签发用户证书失败,构建用户信息时出现错误,请确定用户信息填写正确,且未包含特殊字符!用户名" + x509User.getCn();
                        json = "{success:false,msg:'" + msg + "'}";
                        logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                    }
                } else {
                    msg = "签发用户证书失败,构建用户信息时出现错误,请确定用户信息正确填写!用户名:" + x509User.getCn();
                    json = "{success:false,msg:'" + msg + "'}";
                    logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                }
                PrintWriter writer = response.getWriter();
                writer.write(json);
                writer.flush();
                writer.close();
            }
       }else if(command!=null&&command.length()>0&&command.equals(get_download_key)){
            String cn = request.getParameter("cn");
           /* String idCard = request.getParameter("idCard");
            String province = request.getParameter("province");
            String city = request.getParameter("city");
            String organization = request.getParameter("organization");
            String institution = request.getParameter("institution");
            String phone = request.getParameter("phone");
            String address = request.getParameter("address");
            String userEmail = request.getParameter("userEmail");*/
            String fileName = null;
            json = "{success:false}";
            //签发DN
            String signDn = X509CaXML.getSignDn();
            //数据DN
            String DN = DNUtils.add(signDn, cn);
            //得到父路径
            String dir = DirectoryUtils.getSuperDirectory(DN);
            String subPath = null;
            subPath = dir + cn + X509Context.keyName;
            //得到父路径
          /*  String Agent = request.getHeader("User-Agent");
            StringTokenizer st = new StringTokenizer(Agent, ";");
            st.nextToken();*/
            //得到用户的浏览器名  MSIE  Firefox
//            String userBrowser = st.nextToken();
            File file = new File(subPath);
            if (file.exists()) {
//                FileUtil.downType(response, cn + X509Context.keyName, userBrowser);
                response = FileUtil.copy(file, response);
                logger.info("用户名:"+cn+",请求下载证书私钥,时间:"+new Date());
                //json = "{success:true,fileName:'"+cn + X509Context.keyName+"'}";
            }
          /*  PrintWriter writer = response.getWriter();
            writer.write(json);
            writer.flush();
            writer.close();*/
        } else if(command!=null&&command.length()>0&&command.equals(get_download_cert)){
            String cn = request.getParameter("cn");
           /* String idCard = request.getParameter("idCard");
            String province = request.getParameter("province");
            String city = request.getParameter("city");
            String organization = request.getParameter("organization");
            String institution = request.getParameter("institution");
            String phone = request.getParameter("phone");
            String address = request.getParameter("address");
            String userEmail = request.getParameter("userEmail");*/
            json = "{success:false}";
            //签发DN
            String signDn = X509CaXML.getSignDn();
            //数据DN
            String DN = DNUtils.add(signDn, cn);
            //得到父路径
            String dir = DirectoryUtils.getSuperDirectory(DN);
            String subPath = null;
            subPath = dir + cn + X509Context.certName;
            //得到父路径
           /* String Agent = request.getHeader("User-Agent");
            StringTokenizer st = new StringTokenizer(Agent, ";");
            st.nextToken();*/
            //得到用户的浏览器名  MSIE  Firefox
//            String userBrowser = st.nextToken();
            File file = new File(subPath);
            if (file.exists()) {
//                FileUtil.downType(response, cn + X509Context.certName, userBrowser);
                response = FileUtil.copy(file, response);
                logger.info("用户名:"+cn+",请求下载证书,时间:"+new Date());
//                json = "{success:true,fileName:'"+cn + X509Context.certName+"'}";
            }
          /*  PrintWriter writer = response.getWriter();
            writer.write(json);
            writer.flush();
            writer.close();*/
        }
    }
}
