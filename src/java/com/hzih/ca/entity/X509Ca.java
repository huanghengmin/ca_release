package com.hzih.ca.entity;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-1
 * Time: 上午11:18
 * To change this template use File | Settings | File Templates.
 */
public class X509Ca implements Serializable {
    /**
     * 用户名
     */
    private String  cn;
    /**
     * 数据库唯一标识
     */
    private String dn;
    /**
     * 地区代码
     */
    private String  orgCode;
    /**
     * 私钥密码
     */
    private String  pwd;
    /*
    证书状态
     */
    private String  certStatus;
    /**
     * 证书序列号
     */
    private String  serial;
    /**
     * 私钥BASE64编码
     */
    private String  key;
    /**
     * 开始生效日期
     */
    private String  createDate;
    /**
     * 截至失效日期
     */
    private String  endDate;
    /**
     * 颁发者
     */
    private String  issueCa;
    /**
     * 输出证书类型
     */
    private String  certType;
    /**
     * 私钥长度
     */
    private String  keyLength;
    /**
     * 有效期(天数)
     */
    private String  validity;
    /**
     * 省
     */
    private String  province;
    /**
     * 市
     */
    private String  city;
    /**
     * 组织
     */
    private String  organization;
    /**
     * 机构
     */
    private String  institution;
    /**
     * 描述
     */
    private String  desc;
    /**
     * 输出证书BASE64编码
     */
    private String  certBase64Code;

    private byte[] cACertificateAttr;

    private byte[] certificateRevocationListAttr;

    private byte[] deltaRevocationListAttr;

    private byte[] authorityRevocationListAttr;

    private byte[] crossCertificatePairAttr;

    /**
     * LDAP 存放CA证书的公钥信息
     */
    public static final String DEFAULT_cACertificateAttr     = "cACertificate;binary";

    /**
     * LDAP 存放吊销列表
     */
    public static final String DEFAULT_certificateRevocationListAttr        = "certificateRevocationList;binary";
    public static final String DEFAULT_deltaRevocationListAttr   = "deltaRevocationList;binary";
    public static final String DEFAULT_authorityRevocationListAttr        = "authorityRevocationList;binary";
    /**
     *
     */
    public static final String DEFAULT_crossCertificatePairAttr  = "crossCertificatePair;binary";



    public static String getObjAttr(){
        return "X509Ca";
    }
    public static String getCnAttr(){
        return "cn";
    }
    public static String getDnAttr(){
        return "dn";
    }
    public static String getOrgcodeAttr(){
        return "orgCode";
    }
    public static String getPwdAttr(){
        return "pwd";
    }
    public static String getProvinceAttr(){
        return "province";
    }
    public static String getCityAttr(){
        return "city";
    }
    public static String getOrganizationAttr(){
        return "organization";
    }
    public static String getInstitutionAttr(){
        return "institution";
    }
    public static String getCertStatusAttr(){
        return "certStatus";
    }
    public static String getKeyAttr(){
        return "key";
    }
    public static String getSerialAttr(){
        return "serial";
    }
    public static String getCertBase64CodeAttr(){
        return "certBase64Code";
    }
    public static String getIssueCaAttr(){
        return "issueCa";
    }
    public static String getValidityAttr(){
        return "validity";
    }
    public static String getCreateDateAttr(){
        return "createDate";
    }
    public static String getEndDateAttr(){
        return "endDate";
    }
    public static String getCertTypeAttr(){
        return "certType";
    }
    public static String getKeyLengthAttr(){
        return "keyLength";
    }
    public static String getDescAttr() {
        return "desc";
    }

    public X509Ca(String cn) {
        this.cn = cn;
    }

    public X509Ca() {
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String dn) {
        this.dn = dn;
    }

    public String getOrgCode() {
        return orgCode;
    }

    public void setOrgCode(String orgCode) {
        this.orgCode = orgCode;
    }

    public String getPwd() {
        return pwd;
    }

    public void setPwd(String pwd) {
        this.pwd = pwd;
    }

    public String getCertStatus() {
        return certStatus;
    }

    public void setCertStatus(String certStatus) {
        this.certStatus = certStatus;
    }

    public String getSerial() {
        return serial;
    }

    public void setSerial(String serial) {
        this.serial = serial;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getCreateDate() {
        return createDate;
    }

    public void setCreateDate(String createDate) {
        this.createDate = createDate;
    }

    public String getEndDate() {
        return endDate;
    }

    public void setEndDate(String endDate) {
        this.endDate = endDate;
    }

    public String getIssueCa() {
        return issueCa;
    }

    public void setIssueCa(String issueCa) {
        this.issueCa = issueCa;
    }

    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    public String getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(String keyLength) {
        this.keyLength = keyLength;
    }

    public String getValidity() {
        return validity;
    }

    public void setValidity(String validity) {
        this.validity = validity;
    }

    public String getProvince() {
        return province;
    }

    public void setProvince(String province) {
        this.province = province;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getInstitution() {
        return institution;
    }

    public void setInstitution(String institution) {
        this.institution = institution;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public String getCertBase64Code() {
        return certBase64Code;
    }

    public void setCertBase64Code(String certBase64Code) {
        this.certBase64Code = certBase64Code;
    }

    public byte[] getcACertificateAttr() {
        return cACertificateAttr;
    }

    public void setcACertificateAttr(byte[] cACertificateAttr) {
        this.cACertificateAttr = cACertificateAttr;
    }

    public byte[] getCertificateRevocationListAttr() {
        return certificateRevocationListAttr;
    }

    public void setCertificateRevocationListAttr(byte[] certificateRevocationListAttr) {
        this.certificateRevocationListAttr = certificateRevocationListAttr;
    }

    public byte[] getDeltaRevocationListAttr() {
        return deltaRevocationListAttr;
    }

    public void setDeltaRevocationListAttr(byte[] deltaRevocationListAttr) {
        this.deltaRevocationListAttr = deltaRevocationListAttr;
    }

    public byte[] getAuthorityRevocationListAttr() {
        return authorityRevocationListAttr;
    }

    public void setAuthorityRevocationListAttr(byte[] authorityRevocationListAttr) {
        this.authorityRevocationListAttr = authorityRevocationListAttr;
    }

    public byte[] getCrossCertificatePairAttr() {
        return crossCertificatePairAttr;
    }

    public void setCrossCertificatePairAttr(byte[] crossCertificatePairAttr) {
        this.crossCertificatePairAttr = crossCertificatePairAttr;
    }
}
