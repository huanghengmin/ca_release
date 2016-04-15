package com.hzih.ca.dao.impl;

import com.hzih.ca.dao.X509UserDao;
import com.hzih.ca.entity.X509User;
import com.hzih.ca.web.action.ldap.LdapUtils;
import org.apache.log4j.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-22
 * Time: 下午2:44
 * To change this template use File | Settings | File Templates.
 */
public class X509UserDaoImpl implements X509UserDao {

    private Logger log = Logger.getLogger(X509UserDaoImpl.class);

    @Override
    public boolean add(X509User x509User) throws Exception {
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

        LdapUtils ldapUtils = new LdapUtils();
        DirContext ctx = ldapUtils.getCtx();
        try {
            ctx.createSubcontext(dn.toString(), attr);
            return true;
        } catch (Exception e) {
            log.info("新增用户实体::" + x509User.getDn() + ":出现错误:" + e.getMessage(),e);
        } finally {
            LdapUtils.close(ctx);
        }
        return false;
    }

    @Override
    public boolean modify(X509User x509User) throws Exception {
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
            LdapUtils ldapUtils = new LdapUtils();
            DirContext ctx = ldapUtils.getCtx();
            try {
                ctx.modifyAttributes(x509User.getDn(), mArray);
                return true;
            } catch (Exception e) {
                log.info("修改设备实体::" + x509User.getDn() + ":出现错误:" + e.getMessage(),e);
            } finally {
                LdapUtils.close(ctx);
            }
        }
        return false;
    }

    @Override
    public boolean delete(String DN) throws Exception {
        LdapUtils ldapUtils = new LdapUtils();
        DirContext ctx = ldapUtils.getCtx();
        try {
            ctx.destroySubcontext(DN);
            return true;
        } catch (NamingException e) {
            log.info("删除用户失败::" + DN,e);
        }
        return false;
    }

    @Override
    public boolean exist(String dn) {
        SearchResult sr = LdapUtils.findCurrentNode(dn);
        if(sr!=null){
            return true;
        }
        return false;
    }

}
