package com.hzih.ca.entity.mapper;

import com.hzih.ca.entity.X509Ca;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-5-2
 * Time: 下午4:39
 * To change this template use File | Settings | File Templates.
 */
public class X509CaAttributeMapper {

    public static X509Ca mapFromAttributes(SearchResult sr) throws javax.naming.NamingException {
        X509Ca x509Ca = new X509Ca();

        Attributes attr = sr.getAttributes();

        x509Ca.setCn((String) attr.get(X509Ca.getCnAttr()).get());

        x509Ca.setDn(sr.getNameInNamespace());

        if (attr.get(X509Ca.getOrgcodeAttr()) != null) {
            x509Ca.setOrgCode((String)attr.get(X509Ca.getOrgcodeAttr()).get());
        }
        if (attr.get(X509Ca.getPwdAttr()) != null) {
            x509Ca.setPwd((String)attr.get(X509Ca.getPwdAttr()).get());
        }
        if (attr.get(X509Ca.getCertStatusAttr()) != null) {
            x509Ca.setCertStatus((String)attr.get(X509Ca.getCertStatusAttr()).get());
        }
        if (attr.get(X509Ca.getSerialAttr()) != null) {
            x509Ca.setSerial((String)attr.get(X509Ca.getSerialAttr()).get());
        }
        if (attr.get(X509Ca.getCreateDateAttr()) != null) {
            x509Ca.setCreateDate((String)attr.get(X509Ca.getCreateDateAttr()).get());
        }
        if (attr.get(X509Ca.getEndDateAttr()) != null) {
            x509Ca.setEndDate((String)attr.get(X509Ca.getEndDateAttr()).get());
        }
        if (attr.get(X509Ca.getIssueCaAttr()) != null) {
            x509Ca.setIssueCa((String)attr.get(X509Ca.getIssueCaAttr()).get());
        }
        if (attr.get(X509Ca.getCertTypeAttr()) != null) {
            x509Ca.setCertType((String)attr.get(X509Ca.getCertTypeAttr()).get());
        }
        if (attr.get(X509Ca.getKeyLengthAttr()) != null) {
            x509Ca.setKeyLength((String)attr.get(X509Ca.getKeyLengthAttr()).get());
        }
        if (attr.get(X509Ca.getValidityAttr()) != null) {
            x509Ca.setValidity((String)attr.get(X509Ca.getValidityAttr()).get());
        }
        if (attr.get(X509Ca.getProvinceAttr()) != null) {
            x509Ca.setProvince((String)attr.get(X509Ca.getProvinceAttr()).get());
        }
        if (attr.get(X509Ca.getCityAttr()) != null) {
            x509Ca.setCity((String)attr.get(X509Ca.getCityAttr()).get());
        }
        if (attr.get(X509Ca.getOrganizationAttr()) != null) {
            x509Ca.setOrganization((String)attr.get(X509Ca.getOrganizationAttr()).get());
        }
        if (attr.get(X509Ca.getInstitutionAttr()) != null) {
            x509Ca.setInstitution((String)attr.get(X509Ca.getInstitutionAttr()).get());
        }
        if (attr.get(X509Ca.getDescAttr()) != null) {
            x509Ca.setDesc((String)attr.get(X509Ca.getDescAttr()).get());
        }
        return x509Ca;
    }
}
