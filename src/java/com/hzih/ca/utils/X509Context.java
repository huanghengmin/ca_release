package com.hzih.ca.utils;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-3
 * Time: 上午9:05
 * To change this template use File | Settings | File Templates.
 */
public class X509Context {
    /**
     * 证书存放路径
     */
    public static final String store_path = StringContext.systemPath + "/certificate";

    public static final String config_path = StringContext.systemPath +"/config";

    public static final String license_path = StringContext.systemPath +"/license";

    public static final String security_path = StringContext.systemPath +"/security";
    /**
     * ca 配置文件
     */
    public static final String ca_xml  =  StringContext.systemPath + "/config/ca.xml";
    /**
     * ldap 配置文件
     */
    public static final String ldap_xml  =  StringContext.systemPath + "/config/ldap.xml";

    public static final String ldap_bak_ldif = StringContext.systemPath +"/ldapbak.ldif";

    public static final String mysql_bak_sql = StringContext.systemPath + "/mysqlbak.sql";

    public static final String bak_file = "ca_bak.tar.gz";

    /**
     * 日志服务器配置文件
     */
    public static final String syslog_xml =StringContext.systemPath + "/config/syslog.xml";

    /**
     * 总发证数量
     */
    public static final String license_xml =StringContext.systemPath + "/config/license.xml";
    /**
     * 当前license总数
     */
    public static final int license_count = 3000;

    public static final String keyName = ".key";

    public static final String csrName = ".csr";

    public static final String certName = ".cer";

    public static final String pkcsName = ".pfx";

    public static final String crlName = ".crl";

    public static final String jksName = ".jks";

    public static final String bksName = ".bks";
    /**
     * ca配置文件
     */
    public static final String config_type_ca = ".config";
    /**
     * 请求配置文件
     */
    public static final String config_type_certificate = ".cnf";
    /**
     * 主数据库文件
     */
    public static final String database = "index.txt";
    /**
     * crl数据库文件
     */
    public static final String crl_database = "crlnumber";
    /**
     * 证书序列号数据库文件
     */
    public static final String serial_database = "serial";
    /**
     * 默认字符编码
     */
    public static final String charset = "utf-8";
    /**
     * 中国
     */
    public static final String default_country_code = "CN";

    /**
     * 签发证书默认有效期
     */
    public static final int   default_certificate_validity = 1825;
    /**
     * CA默认有效期
     */
    public static final int   default_ca_validity = 3650;

    /**
    证书类型
    */

    //根证书
    public static final String certificate_type_ca = "v3_ca";
    // 代码签名
    public static final String certificate_type_codeSignature = "certificate_codeSignature";
    //计算机
    public static final String certificate_type_computer = "certificate_computer";
    //服务器证书
    public static final String certificate_type_server = "certificate_server";
    // 客户端证书
    public static final String certificate_type_client = "certificate_client";
     // 信息列表签名
    public static final String certificate_type_trustListSignature = "certificate_trustListSignature";
    // 时间戳
    public static final String certificate_type_timestamp = "certificate_timestamp";
     // ipsec
    public static final String certificate_type_ipsec = "certificate_ipsec";
     // email
    public static final String certificate_type_email = "certificate_email";
     //智能卡登陆
    public static final String certificate_type_smartCardLogin = "certificate_smartCardLogin";
     // crl
    public static final String crl_extends = "crl_extends";
    // crl吊销点
    public static final String crl_dps = "crl_dps";

    /**
     * 扩展
     */

    /**
     * 基本限制
     * 例如：
     basicConstraints=CA:TRUE
     basicConstraints=CA:FALSE
     basicConstraints=critical,CA:TRUE, pathlen:0

     basicConstraints=critical,CA:TRUE,pathlen:1
     */
    public static final String extend_basicConstraints = "basicConstraints";
    /**
     * 使用者密钥标识符
     *  例如：
     *  subjectKeyIdentifier=hash
     */
    public static final String extend_subjectKeyIdentifier = "subjectKeyIdentifier";
    /**
     * 颁发机构密钥标识符
     * 例如：
     * authorityKeyIdentifier=keyid,issuer
     */
    public static final String extend_authorityKeyIdentifier = "authorityKeyIdentifier";
    /**
     * 使用者备用名称
     *  例如:
     subjectAltName=email:copy,email:my@other.address,URI:http://my.url.here/
     subjectAltName=IP:192.168.7.1
     subjectAltName=IP:13::17
     subjectAltName=email:my@other.address,RID:1.2.3.4
     subjectAltName=otherName:1.2.3.4;UTF8:some other identifier
     subjectAltName=dirName:dir_sect
     [dir_sect]
     C=UK
     O=My Organization
     OU=My Unit
     CN=My Name

     subjectAltName = email:copy,DNS:hpxs,email:hpxs@hotmail.com,RID:1.2.3.4,URI:https://hpxs,IP:192.168.0.22
     */
    public static final String extend_subjectAltName = "subjectAltName";
    /**
     * 颁发机构备用名称
     * 例如:
     * issuserAltName = issuer:copy
     *
     * issuserAltName = DNS:hpxs,email:hpxs@hotmail.com,RID:1.2.3.4,URI:https://hpxs,IP:192.168.0.22
     */
    public static final String extend_issuserAltName ="issuserAltName";
    /**
     * 权威信息访问
     例如:
     authorityInfoAccess = OCSP;URI:http://ocsp.my.host/
     authorityInfoAccess = caIssuers;URI:http://my.ca/ca.html
     */
    public static final String extend_authorityInfoAccess ="authorityInfoAccess";
    /**
     * CRL颁发点
         简单实例:
         crlDistributionPoints=URI:http://myhost.com/myca.crl
         crlDistributionPoints=URI:http://my.com/my.crl,URI:http://oth.com/my.crl
         完整实例:
         crlDistributionPoints=crldp1_section
         [crldp1_section]
         fullname=URI:http://myhost.com/myca.crl
         CRLissuer=dirName:issuer_sect
         reasons=keyCompromise, CACompromise
         [issuer_sect]
         C=UK
         O=Organisation
         CN=Some Name
     */
    public static final String extend_crlDistributionPoints = "crlDistributionPoints";
    /**
     * 签发点
     例如:
         issuingDistributionPoint=critical, @idp_section
         [idp_section]
         fullname=URI:http://myhost.com/myca.crl
         indirectCRL=TRUE
         onlysomereasons=keyCompromise, CACompromise
         [issuer_sect]
         C=UK
         O=Organisation
         CN=Some Name
     */
    public static final String extend_issuingDistributionPoint = "issuingDistributionPoint";
    /**
     * 证书策略
     例如:
         certificatePolicies=ia5org,1.2.3.4,1.5.6.7.8,@polsect
         [polsect]
        policyIdentifier = 1.3.5.8
        CPS.1="http://my.host.name/";
        CPS.2="http://my.your.name/";
        userNotice.1=@notice
        [notice]
        explicitText="Explicit Text Here"
        organization="Organisation Name"
        noticeNumbers=1,2,3,4
     */
    public static final String extend_certificatePolicies = "certificatePolicies";
    /**
     * 策略限制
     * 例如:
     * policyConstraints = requireExplicitPolicy:3
     */
    public static final String extend_policyConstraints = "policyConstraints";
    /**
     * 抑制任何政策
     * 例如：
     * inhibitAnyPolicy = 2
     */
    public static final String extend_inhibitAnyPolicy = "inhibitAnyPolicy";
    /**
     * 名称限制
     * 例如：
        nameConstraints=permitted;IP:192.168.0.0/255.255.0.0
        nameConstraints=permitted;email:.somedomain.com
        nameConstraints=excluded;email:.com
     */
    public static final String extend_nameConstraints = "nameConstraints";
    /**
     * OCSP noCheck
     * 例如：noCheck = ignored
     */
    public static final String extend_noCheck = "noCheck";


    /**
     * Netscape String extensions
     */

    //注释
    public static final String nsString_nsComment = "nsComment";
    //基本链接
    public static final String nsString_nsBaseUrl = "nsBaseUrl";
    //吊销服务链接
    public static final String nsString_nsRevocationUrl = "nsRevocationUrl";
    //颁发者吊销链接
    public static final String nsString_nsCaRevocationUrl = "nsCaRevocationUrl";
    //证书更新链接
    public static final String nsString_nsRenewalUrl = "nsRenewalUrl";
    //颁发者政策链接
    public static final String nsString_nsCaPolicyUrl  = "nsCaPolicyUrl";
    //加密服务器名称
    public static final String nsString_nsSslServerName = "nsSslServerName";

    /**
     * Netscape Certificate Type
     */

    //SSL Client
    public static final String nsCertificate_client = "client";
    //SSL Server
    public static final String nsCertificate_server = "server";
    //S/MIME
    public static final String nsCertificate_email = "email";
    //Object Signing
    public static final String nsCertificate_objsign = "objsign";
    //
    public static final String nsCertificate_reserved = "reserved";
    //SSL CA
    public static final String nsCertificate_sslCA = "sslCA";
    //S/MIME CA
    public static final String nsCertificate_emailCA = "emailCA";
    //Object Signing CA
    public static final String nsCertificate_objCA = "objCA";
}
