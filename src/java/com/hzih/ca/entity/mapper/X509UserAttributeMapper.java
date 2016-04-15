package com.hzih.ca.entity.mapper;

import com.hzih.ca.entity.X509User;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-5-2
 * Time: 下午4:46
 * To change this template use File | Settings | File Templates.
 */
public class X509UserAttributeMapper {

    public static X509User mapFromAttributes(SearchResult sr) throws javax.naming.NamingException {
        X509User x509User = new X509User();

        Attributes attr = sr.getAttributes();

        x509User.setCn((String) attr.get(X509User.getCnAttr()).get());

        x509User.setDn(sr.getNameInNamespace());

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
        if (attr.get(x509User.getOrgcodeAttr()) != null) {
            x509User.setOrgCode((String)attr.get(x509User.getOrgcodeAttr()).get());
        }
        if (attr.get(x509User.getPwdAttr()) != null) {
            x509User.setPwd((String)attr.get(x509User.getPwdAttr()).get());
        }
        if (attr.get(x509User.getCertStatusAttr()) != null) {
            x509User.setCertStatus((String)attr.get(x509User.getCertStatusAttr()).get());
        }
        if (attr.get(x509User.getSerialAttr()) != null) {
            x509User.setSerial((String)attr.get(x509User.getSerialAttr()).get());
        }
        if (attr.get(x509User.getCreateDateAttr()) != null) {
            x509User.setCreateDate((String)attr.get(x509User.getCreateDateAttr()).get());
        }
        if (attr.get(x509User.getEndDateAttr()) != null) {
            x509User.setEndDate((String)attr.get(x509User.getEndDateAttr()).get());
        }
        if (attr.get(x509User.getIssueCaAttr()) != null) {
            x509User.setIssueCa((String)attr.get(x509User.getIssueCaAttr()).get());
        }
        if (attr.get(x509User.getCertTypeAttr()) != null) {
            x509User.setCertType((String)attr.get(x509User.getCertTypeAttr()).get());
        }
        if (attr.get(x509User.getKeyLengthAttr()) != null) {
            x509User.setKeyLength((String)attr.get(x509User.getKeyLengthAttr()).get());
        }
        if (attr.get(x509User.getValidityAttr()) != null) {
            x509User.setValidity((String)attr.get(x509User.getValidityAttr()).get());
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
        if (attr.get(x509User.getDescAttr()) != null) {
            x509User.setDesc((String)attr.get(x509User.getDescAttr()).get());
        }
        return x509User;
    }
}
