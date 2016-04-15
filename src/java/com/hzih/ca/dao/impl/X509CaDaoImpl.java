package com.hzih.ca.dao.impl;

import com.hzih.ca.dao.X509CaDao;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;
import com.hzih.ca.web.action.ldap.LdapUtils;
import org.apache.log4j.Logger;

import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-21
 * Time: 下午2:56
 * To change this template use File | Settings | File Templates.
 */
public class X509CaDaoImpl implements X509CaDao {
    private Logger log = Logger.getLogger(X509CaDaoImpl.class);

    @Override
    public boolean add(DirContext ctx, X509Ca x509Ca)  {

        BasicAttribute ba = new BasicAttribute("objectclass");
        ba.add(X509Ca.getObjAttr()); //此处的X509Ca对应的是core.schema文件中的objectClass：X509Ca
        Attributes attr = new BasicAttributes();
        attr.put(ba);
        //必填属性，不能为null也不能为空字符串
        attr.put(X509Ca.getCnAttr(), x509Ca.getCn());
        //可选字段需要判断是否为空，如果为空则不能添加
        if (x509Ca.getOrgCode() != null&&x509Ca.getOrgCode().length()>0) {
            attr.put(X509Ca.getOrgcodeAttr(), x509Ca.getOrgCode());
        }
        if (x509Ca.getPwd() != null&&x509Ca.getPwd().length()>0) {
            attr.put(X509Ca.getPwdAttr(), x509Ca.getPwd());
        }
        if (x509Ca.getCertStatus() != null&&x509Ca.getCertStatus().length()>0) {
            attr.put(X509Ca.getCertStatusAttr(), x509Ca.getCertStatus());
        }
        if (x509Ca.getSerial() != null&&x509Ca.getSerial().length()>0) {
            attr.put(X509Ca.getSerialAttr(), x509Ca.getSerial());
        }
        if (x509Ca.getKey() != null&&x509Ca.getKey().length()>0) {
            attr.put(X509Ca.getKeyAttr(), x509Ca.getKey());
        }
        if (x509Ca.getCreateDate() != null&&x509Ca.getCreateDate().length()>0) {
            attr.put(X509Ca.getCreateDateAttr(), x509Ca.getCreateDate());
        }
        if (x509Ca.getEndDate() != null&&x509Ca.getEndDate().length()>0) {
            attr.put(X509Ca.getEndDateAttr(), x509Ca.getEndDate());
        }
        if (x509Ca.getIssueCa() != null&&x509Ca.getIssueCa().length()>0) {
            attr.put(X509Ca.getIssueCaAttr(), x509Ca.getIssueCa());
        }
        if (x509Ca.getCertType() != null&&x509Ca.getCertType().length()>0) {
            attr.put(X509Ca.getCertTypeAttr(), x509Ca.getCertType());
        }
        if (x509Ca.getKeyLength() != null&&x509Ca.getKeyLength().length()>0) {
            attr.put(X509Ca.getKeyLengthAttr(), x509Ca.getKeyLength());
        }
        if (x509Ca.getValidity() != null&&x509Ca.getValidity().length()>0) {
            attr.put(X509Ca.getValidityAttr(), x509Ca.getValidity());
        }
        if (x509Ca.getProvince() != null&&x509Ca.getProvince().length()>0) {
            attr.put(X509Ca.getProvinceAttr(), x509Ca.getProvince());
        }
        if (x509Ca.getCity() != null&&x509Ca.getCity().length()>0) {
            attr.put(X509Ca.getCityAttr(), x509Ca.getCity());
        }
        if (x509Ca.getOrganization() != null&&x509Ca.getOrganization().length()>0) {
            attr.put(X509Ca.getOrganizationAttr(), x509Ca.getOrganization());
        }
        if (x509Ca.getInstitution() != null&&x509Ca.getInstitution().length()>0) {
            attr.put(X509Ca.getInstitutionAttr(), x509Ca.getInstitution());
        }
        if (x509Ca.getDesc() != null&&x509Ca.getDesc().length()>0) {
            attr.put(X509Ca.getDescAttr(), x509Ca.getDesc());
        }
        if (x509Ca.getCertBase64Code() != null&&x509Ca.getCertBase64Code().length()>0) {
            attr.put(X509Ca.getCertBase64CodeAttr(), x509Ca.getCertBase64Code());
        }
        if (x509Ca.getcACertificateAttr() != null) {
            attr.put(X509Ca.DEFAULT_cACertificateAttr, x509Ca.getcACertificateAttr());
        }
        if (x509Ca.getCertificateRevocationListAttr() != null) {
            attr.put(X509Ca.DEFAULT_certificateRevocationListAttr, x509Ca.getCertificateRevocationListAttr());
        }
        if (x509Ca.getDeltaRevocationListAttr() != null) {
            attr.put(X509Ca.DEFAULT_deltaRevocationListAttr, x509Ca.getDeltaRevocationListAttr());
        }
        if (x509Ca.getAuthorityRevocationListAttr() != null) {
            attr.put(X509Ca.DEFAULT_authorityRevocationListAttr, x509Ca.getAuthorityRevocationListAttr());
        }
        if (x509Ca.getCrossCertificatePairAttr() != null) {
            attr.put(X509Ca.DEFAULT_crossCertificatePairAttr, x509Ca.getCrossCertificatePairAttr());
        }
        String issueCa = x509Ca.getIssueCa();
        if ("".equals(issueCa)||issueCa ==null) {
            issueCa = LdapXMLUtils.getValue(LdapXMLUtils.base);
        }
        attr.put(X509Ca.getIssueCaAttr(),issueCa);
        String dn = DNUtils.add(issueCa,x509Ca.getCn());
        try {
            ctx.createSubcontext(dn, attr);
            return true;
        } catch (NamingException e) {
            log.error(e.getMessage(),e);
           return false;
        }
    }

    @Override
    public boolean modify(DirContext ctx, X509Ca x509Ca) {
        if (x509Ca == null || x509Ca.getCn() == null|| x509Ca.getCn().length() <= 0) {
            return false;
        }
        List<ModificationItem> mList = new ArrayList<ModificationItem>();
        if(x509Ca.getOrgCode()!=null&&x509Ca.getOrgCode().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getOrgcodeAttr(),x509Ca.getOrgCode())));
        if(x509Ca.getPwd()!=null&&x509Ca.getPwd().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getPwdAttr(),x509Ca.getPwd())));
        if(x509Ca.getCertStatus()!=null&&x509Ca.getCertStatus().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getCertStatusAttr(),x509Ca.getCertStatus())));
        if(x509Ca.getSerial()!=null&&x509Ca.getSerial().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getSerialAttr(),x509Ca.getSerial())));
        if(x509Ca.getKey()!=null&&x509Ca.getKey().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getKeyAttr(),x509Ca.getKey())));
        if(x509Ca.getCreateDate()!=null&&x509Ca.getCreateDate().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getCreateDateAttr(),x509Ca.getCreateDate())));
        if(x509Ca.getEndDate()!=null&&x509Ca.getEndDate().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getEndDateAttr(),x509Ca.getEndDate())));
        if(x509Ca.getIssueCa()!=null&&x509Ca.getIssueCa().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getIssueCaAttr(),x509Ca.getIssueCa())));
        if(x509Ca.getCertType()!=null&&x509Ca.getCertType().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getCertTypeAttr(),x509Ca.getCertType())));
        if(x509Ca.getKeyLength()!=null&&x509Ca.getKeyLength().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getKeyLengthAttr(),x509Ca.getKeyLength())));
        if(x509Ca.getValidity()!=null&&x509Ca.getValidity().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getValidityAttr(),x509Ca.getValidity())));
        if(x509Ca.getProvince()!=null&&x509Ca.getProvince().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getProvinceAttr(),x509Ca.getProvince())));
        if(x509Ca.getCity()!=null&&x509Ca.getCity().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getCityAttr(),x509Ca.getCity())));
        if(x509Ca.getOrganization()!=null&&x509Ca.getOrganization().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getOrganizationAttr(),x509Ca.getOrganization())));
        if(x509Ca.getInstitution()!=null&&x509Ca.getInstitution().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getInstitutionAttr(),x509Ca.getInstitution())));
        if(x509Ca.getDesc()!=null&&x509Ca.getDesc().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getDescAttr(),x509Ca.getDesc())));
        if(x509Ca.getCertBase64Code()!=null&&x509Ca.getCertBase64Code().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.getCertBase64CodeAttr(),x509Ca.getCertBase64Code())));
        if(x509Ca.getcACertificateAttr()!=null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.DEFAULT_cACertificateAttr,x509Ca.getcACertificateAttr())));
        if(x509Ca.getCertificateRevocationListAttr()!=null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.DEFAULT_certificateRevocationListAttr,x509Ca.getCertificateRevocationListAttr())));
        if(x509Ca.getAuthorityRevocationListAttr()!=null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.DEFAULT_authorityRevocationListAttr,x509Ca.getAuthorityRevocationListAttr())));
        if(x509Ca.getDeltaRevocationListAttr()!=null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.DEFAULT_deltaRevocationListAttr,x509Ca.getDeltaRevocationListAttr())));
        if(x509Ca.getCrossCertificatePairAttr()!=null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Ca.DEFAULT_crossCertificatePairAttr,x509Ca.getCrossCertificatePairAttr())));
        if (mList.size() > 0) {
            ModificationItem[] mArray = new ModificationItem[mList.size()];
            for (int i = 0; i < mList.size(); i++) {
                mArray[i] = mList.get(i);
            }
            //modifyAttributes 方法是修改对象的操作，与rebind（）方法需要区别开
            try{
                ctx.modifyAttributes(x509Ca.getDn(), mArray);
                return true;
            }catch (Exception e){
                log.info("更新证书不成功!" + e.getMessage(),e);
                return false;
            }
        }
        return false;
    }


    @Override
    public boolean deleteStation(DirContext ctx, String DN)  {
        return LdapUtils.delNode(SearchControls.SUBTREE_SCOPE, DN, "(objectclass=*)", ctx);
    }

}
