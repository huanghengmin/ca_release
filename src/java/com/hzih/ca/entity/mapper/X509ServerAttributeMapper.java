package com.hzih.ca.entity.mapper;

import com.hzih.ca.entity.X509Server;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-5-2
 * Time: 下午4:46
 * To change this template use File | Settings | File Templates.
 */
public class X509ServerAttributeMapper  {

    public static X509Server mapFromAttributes(SearchResult sr) throws javax.naming.NamingException {
        X509Server x509Server = new X509Server();

        Attributes attr = sr.getAttributes();

        x509Server.setCn((String) attr.get(X509Server.getCnAttr()).get());

        x509Server.setDn(sr.getNameInNamespace());

        if (attr.get(X509Server.getServerIpAttr()) != null) {
            x509Server.setServerIp((String) attr.get(X509Server.getServerIpAttr()).get());
        }
        if (attr.get(x509Server.getOrgcodeAttr()) != null) {
            x509Server.setOrgCode((String)attr.get(x509Server.getOrgcodeAttr()).get());
        }
        if (attr.get(x509Server.getPwdAttr()) != null) {
            x509Server.setPwd((String)attr.get(x509Server.getPwdAttr()).get());
        }
        if (attr.get(x509Server.getCertStatusAttr()) != null) {
            x509Server.setCertStatus((String)attr.get(x509Server.getCertStatusAttr()).get());
        }
        if (attr.get(x509Server.getSerialAttr()) != null) {
            x509Server.setSerial((String)attr.get(x509Server.getSerialAttr()).get());
        }
        if (attr.get(x509Server.getCreateDateAttr()) != null) {
            x509Server.setCreateDate((String)attr.get(x509Server.getCreateDateAttr()).get());
        }
        if (attr.get(x509Server.getEndDateAttr()) != null) {
            x509Server.setEndDate((String)attr.get(x509Server.getEndDateAttr()).get());
        }
        if (attr.get(x509Server.getIssueCaAttr()) != null) {
            x509Server.setIssueCa((String)attr.get(x509Server.getIssueCaAttr()).get());
        }
        if (attr.get(x509Server.getCertTypeAttr()) != null) {
            x509Server.setCertType((String)attr.get(x509Server.getCertTypeAttr()).get());
        }
        if (attr.get(x509Server.getKeyLengthAttr()) != null) {
            x509Server.setKeyLength((String)attr.get(x509Server.getKeyLengthAttr()).get());
        }
        if (attr.get(x509Server.getValidityAttr()) != null) {
            x509Server.setValidity((String)attr.get(x509Server.getValidityAttr()).get());
        }
        if (attr.get(x509Server.getProvinceAttr()) != null) {
            x509Server.setProvince((String)attr.get(x509Server.getProvinceAttr()).get());
        }
        if (attr.get(x509Server.getCityAttr()) != null) {
            x509Server.setCity((String)attr.get(x509Server.getCityAttr()).get());
        }
        if (attr.get(x509Server.getOrganizationAttr()) != null) {
            x509Server.setOrganization((String)attr.get(x509Server.getOrganizationAttr()).get());
        }
        if (attr.get(x509Server.getInstitutionAttr()) != null) {
            x509Server.setInstitution((String)attr.get(x509Server.getInstitutionAttr()).get());
        }
        if (attr.get(x509Server.getDescAttr()) != null) {
            x509Server.setDesc((String)attr.get(x509Server.getDescAttr()).get());
        }
        return x509Server;
    }
}
