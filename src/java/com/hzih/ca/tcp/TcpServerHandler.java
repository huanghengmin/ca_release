package com.hzih.ca.tcp;

import com.hzih.ca.dao.impl.X509UserDaoImpl;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.entity.X509User;
import com.hzih.ca.entity.mapper.X509CaAttributeMapper;
import com.hzih.ca.utils.StringContext;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ca.X509CaXML;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import com.hzih.ca.web.utils.CertificateUtils;
import com.hzih.ca.web.utils.DirectoryUtils;
import com.hzih.ca.web.utils.X509ShellUtils;
import com.hzih.ca.web.utils.X509UserConfigUtils;
import com.hzih.ca.entity.*;
import com.hzih.ca.utils.mina.MessageInfo;
import com.hzih.ca.utils.FileUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;

import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import java.io.File;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created with IntelliJ IDEA.
 * User: sunny
 * Date: 14-7-25
 * Time: 上午10:26
 */
public class TcpServerHandler extends IoHandlerAdapter {
    final static Logger logger = Logger.getLogger(TcpServer.class);


    public TcpServerHandler() {

    }

    public void messageReceived(IoSession session, Object message)
            throws Exception {
        if(message instanceof MessageInfo) {
            MessageInfo messageInfo = (MessageInfo) message;
            String charset = messageInfo.getCharset();
            String bodyStr = new String(messageInfo.getBody(),charset);
            logger.info(session.getRemoteAddress()+ " 发送了 "+bodyStr);
            String responseBody;
            if(bodyStr!=null ){
                    String body = AESDecoder(bodyStr);
                    String cmdType = body.substring(body.indexOf("<CmdType>")+9,body.indexOf("</CmdType>")).trim();
                    if(SipType.DownCA.equalsIgnoreCase(cmdType)) { //ca 下载ca证书
                        DownRequest down = new DownRequest().xmlToBean(body.getBytes(charset));
                        DownCAResponse response = new DownCAResponse();
                        ServiceUtils serviceUtils = ServiceUtils.getService();
                        response.setDeviceId(serviceUtils.deviceId);
                        response.setCmdType(down.getCmdType());
                        response.setDeviceType(down.getDeviceType());

                        File crtFile = getFile(down, "crt");
                        File keyFile = getFile(down, "key");

                        response.setKeyFileName(new String(Base64.encodeBase64("client.key".getBytes())));
                        response.setKeyFileSize(keyFile.length());
                        response.setKeyFile(FileUtil.encodeBase64FileTOString(keyFile.getPath()));

                        response.setCrtFileName(new String(Base64.encodeBase64("client.crt".getBytes())));
                        response.setCrtFileSize(crtFile.length());
                        response.setCrtFile(FileUtil.encodeBase64FileTOString(crtFile.getPath()));

                        response.setResult(SipXml.ResultSuccess);
                        responseBody = AESEncoder(response.toString());
                    } else if(SipType.ApplyCA.equalsIgnoreCase(cmdType)) { //ca 申请证书
                        ApplyRequest apply = new ApplyRequest().xmlToBean(body.getBytes(charset));
                        //TODO 申请证书的信息入库
                        //生成证书
                        ServiceUtils serviceUtils = ServiceUtils.getService();
                        ApplyResponse response = new ApplyResponse();
                        response.setResult(SipXml.ResultFailure);
                        String msg = null;
                        String json = null;
                        String cn = apply.getDeviceId();
                        String idCard = "000000000000000000";
                        String province = apply.getProvince();
                        String city = apply.getCity();
                        String organization = apply.getOrganization();
                        String institution = apply.getInstitution();
                        String phone = "0000000";//request.getParameter("phone");
                        String address = apply.getAddress();
                        String userEmail = "0000@QQ.com";//request.getParameter("userEmail");
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
                                                X509UserDaoImpl x509UserDaoImpl = new X509UserDaoImpl();
                                                boolean exist_flag =  x509UserDaoImpl.exist(dn);
                                                if(exist_flag){
                                                    save_flag = x509UserDaoImpl.modify(x509User);
                                                    if (save_flag) {
                                                        msg = "更新用户证书成功,用户名:" + x509User.getCn();
                                                        json = "{success:true,msg:'" + msg + "'}";
                                                        logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                                        response.setResult(SipXml.ResultFailure);
                                                    }else {
                                                        msg = "更新用户证书失败,保存到LDAP数据库失败,用户名:" + x509User.getCn();
                                                        json = "{success:false,msg:'" + msg + "'}";
                                                        logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                                        response.setResult(SipXml.ResultFailure);
                                                    }
                                                }else {
                                                    save_flag = x509UserDaoImpl.add(x509User);
                                                    if (save_flag) {
                                                        msg = "签发用户证书成功,用户名:" + x509User.getCn();
                                                        json = "{success:true,msg:'" + msg + "'}";
                                                        logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                                        response.setResult(SipXml.ResultSuccess);
                                                    } else {
                                                        msg = "签发用户证书失败,保存到LDAP数据库失败,用户名:" + x509User.getCn();
                                                        json = "{success:false,msg:'" + msg + "'}";
                                                        logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                                        response.setResult(SipXml.ResultFailure);
                                                    }
                                                }
                                            } catch (Exception e) {
                                                logger.error(e.getMessage(),e);
                                                response.setResult(SipXml.ResultFailure);
                                            }
                                        } else {
                                            msg = "签发用户证书失败,构建PKCS文件出现错误!用户名:" + x509User.getCn();
                                            json = "{success:false,msg:'" + msg + "'}";
                                            logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                            response.setResult(SipXml.ResultFailure);
                                        }
                                    } else {
                                        msg = "签发用户证书失败,签发时出现错误!用户名:" + x509User.getCn();
                                        json = "{success:false,msg:'" + msg + "'}";
                                        logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                        response.setResult(SipXml.ResultFailure);
                                    }
                                } else {
                                    msg = "签发用户证书失败,构建用户信息时出现错误,请确定用户信息填写正确,且未包含特殊字符!用户名" + x509User.getCn();
                                    json = "{success:false,msg:'" + msg + "'}";
                                    logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                    response.setResult(SipXml.ResultFailure);
                                }
                            } else {
                                msg = "签发用户证书失败,构建用户信息时出现错误,请确定用户信息正确填写!用户名:" + x509User.getCn();
                                json = "{success:false,msg:'" + msg + "'}";
                                logger.info("请求类型:外部请求" + ",请求时间:" + new Date() + ",请求响应:" + msg);
                                response.setResult(SipXml.ResultFailure);
                            }
                        }
                        response.setDeviceId(serviceUtils.deviceId);
                        response.setCmdType(apply.getCmdType());
                        response.setDeviceType(apply.getDeviceType());
                        responseBody = AESEncoder(response.toString());
                    } else {
                        responseBody = "<?xml version=\"1.0\">\r\n\r\n<Response>\r\n<default>"+System.currentTimeMillis()+"</default>\r\n</Response>";
                        responseBody = AESEncoder(responseBody);
                    }
            } else {
                responseBody = "<?xml version=\"1.0\">\r\n\r\n<Response>\r\n<default>"+System.currentTimeMillis()+"</default>\r\n<msg>request body is null</msg>\r\n</Response>";
            }
            byte[] body = responseBody.getBytes(charset);
            messageInfo = new MessageInfo();
            messageInfo.setVersion(MessageInfo.Version);
            messageInfo.setBodyLen(body.length);
            messageInfo.setReserved(new byte[21]);
            messageInfo.setBody(body);
            session.write(messageInfo);
        } else {
            logger.info("string:" + message.toString());

        }
    }

    private File getFile(DownRequest request,String type) {
        if("strategy".equals(type)) {
            if(SipType.Win.equals(request.getOsType())) {
                return new File(StringContext.systemPath+"/config/strategy.xml");
            }
        } else if("ovpn".equals(type)) {
            if(SipType.Win.equals(request.getOsType())) {
                return new File(StringContext.systemPath+"/client_config/VPN_windows.ovpn");
            } else {
                return new File(StringContext.systemPath+"/client_config/VPN_phone.ovpn");
            }
        } else if("ca".equals(type)) {
            if(SipType.Win.equals(request.getOsType())) {
                if(SipType.DownConfig.equalsIgnoreCase(request.getCmdType())) {
                    return new File(StringContext.systemPath+"/ssl/ca/ca.pem");
                }
            }
        }else if("ta".equals(type)) {
            if(SipType.Win.equals(request.getOsType())) {
                if(SipType.DownConfig.equalsIgnoreCase(request.getCmdType())) {
                    return new File(StringContext.systemPath+"/static_key/ta.key");
                }
            }
        } else if("key".equals(type)) {
            if(SipType.Win.equals(request.getOsType())) {
                if(SipType.DownCA.equalsIgnoreCase(request.getCmdType())) {
                    if(request.getDeviceId()!=null) {
                        return new File(StringContext.systemPath + "/certificate/"+X509CaXML.getValue(X509CaXML.cn)+"/"+request.getDeviceId()+".key");
                    }
                }
            }
        } else if("crt".equals(type)) {
            if(SipType.Win.equals(request.getOsType())) {
                if(SipType.DownCA.equalsIgnoreCase(request.getCmdType())) {
                    if(request.getDeviceId()!=null) {
                        return new File(StringContext.systemPath + "/certificate/"+X509CaXML.getValue(X509CaXML.cn)+"/"+request.getDeviceId()+".cer");
                    }
                }
            }
        }
        return null;
    }

    private String AESDecoder(String bodyStr) {

        byte[] decryptResult = Base64.decodeBase64(bodyStr.getBytes());
        return new String(decryptResult);
    }

    private String AESEncoder(String bodyStr) {
        byte[] encryptResult = Base64.encodeBase64(bodyStr.getBytes());
        return new String(encryptResult);
    }

    @Override
    public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
        logger.info("Disconnecting the idle.");
    }

    public void exceptionCaught(IoSession session, Throwable cause) {
        logger.warn(cause.getMessage(),cause);
        session.close(true);
    }
}
