package com.hzih.ca.dao.impl;

import com.hzih.ca.dao.X509ServerDao;
import com.hzih.ca.entity.X509Server;
import com.hzih.ca.web.action.ldap.LdapUtils;
import org.apache.log4j.Logger;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-22
 * Time: 下午2:45
 * To change this template use File | Settings | File Templates.
 */
public class X509ServerDaoImpl implements X509ServerDao {
    private Logger log = Logger.getLogger(X509ServerDaoImpl.class);

    @Override
    public boolean add(X509Server x509Server) throws Exception {
        BasicAttribute ba = new BasicAttribute("objectclass");
        ba.add(X509Server.getObjAttr()); //此处的x509Server对应的是core.schema文件中的objectClass：x509Server
        Attributes attr = new BasicAttributes();
        attr.put(ba);
        //必填属性，不能为null也不能为空字符串
        attr.put(X509Server.getCnAttr(), x509Server.getCn());
        //可选字段需要判断是否为空，如果为空则不能添加
        if (x509Server.getServerIp() != null && x509Server.getServerIp().length() > 0) {
            attr.put(X509Server.getServerIpAttr(), x509Server.getServerIp());
        }
        if (x509Server.getOrgCode() != null && x509Server.getOrgCode().length() > 0) {
            attr.put(X509Server.getOrgcodeAttr(), x509Server.getOrgCode());
        }
        if (x509Server.getPwd() != null && x509Server.getPwd().length() > 0) {
            attr.put(X509Server.getPwdAttr(), x509Server.getPwd());
        }
        if (x509Server.getCertStatus() != null && x509Server.getCertStatus().length() > 0) {
            attr.put(X509Server.getCertStatusAttr(), x509Server.getCertStatus());
        }
        if (x509Server.getSerial() != null && x509Server.getSerial().length() > 0) {
            attr.put(X509Server.getSerialAttr(), x509Server.getSerial());
        }
        if (x509Server.getKey() != null && x509Server.getKey().length() > 0) {
            attr.put(X509Server.getKeyAttr(), x509Server.getKey());
        }
        if (x509Server.getCreateDate() != null && x509Server.getCreateDate().length() > 0) {
            attr.put(X509Server.getCreateDateAttr(), x509Server.getCreateDate());
        }
        if (x509Server.getEndDate() != null && x509Server.getEndDate().length() > 0) {
            attr.put(X509Server.getEndDateAttr(), x509Server.getEndDate());
        }
        if (x509Server.getIssueCa() != null && x509Server.getIssueCa().length() > 0) {
            attr.put(X509Server.getIssueCaAttr(), x509Server.getIssueCa());
        }
        if (x509Server.getCertType() != null && x509Server.getCertType().length() > 0) {
            attr.put(X509Server.getCertTypeAttr(), x509Server.getCertType());
        }
        if (x509Server.getKeyLength() != null && x509Server.getKeyLength().length() > 0) {
            attr.put(X509Server.getKeyLengthAttr(), x509Server.getKeyLength());
        }
        if (x509Server.getValidity() != null && x509Server.getValidity().length() > 0) {
            attr.put(X509Server.getValidityAttr(), x509Server.getValidity());
        }
        if (x509Server.getProvince() != null && x509Server.getProvince().length() > 0) {
            attr.put(X509Server.getProvinceAttr(), x509Server.getProvince());
        }
        if (x509Server.getCity() != null && x509Server.getCity().length() > 0) {
            attr.put(X509Server.getCityAttr(), x509Server.getCity());
        }
        if (x509Server.getOrganization() != null && x509Server.getOrganization().length() > 0) {
            attr.put(X509Server.getOrganizationAttr(), x509Server.getOrganization());
        }
        if (x509Server.getInstitution() != null && x509Server.getInstitution().length() > 0) {
            attr.put(X509Server.getInstitutionAttr(), x509Server.getInstitution());
        }
        if (x509Server.getDesc() != null && x509Server.getDesc().length() > 0) {
            attr.put(X509Server.getDescAttr(), x509Server.getDesc());
        }
        if (x509Server.getCertBase64Code() != null && x509Server.getCertBase64Code().length() > 0) {
            attr.put(X509Server.getCertBase64CodeAttr(), x509Server.getCertBase64Code());
        }
        if (x509Server.getUserCertificateAttr() != null) {
            attr.put(X509Server.DEFAULT_userCertificateAttr, x509Server.getUserCertificateAttr());
        }
        StringBuilder dn = new StringBuilder(X509Server.getCnAttr() + "=" + x509Server.getCn()).append("," + x509Server.getIssueCa());

        LdapUtils ldapUtils = new LdapUtils();
        DirContext ctx = ldapUtils.getCtx();
        try {
            ctx.createSubcontext(dn.toString(), attr);
            return true;
        } catch (Exception e){
            log.info("新增设备实体::"+x509Server.getDn()+":出现错误:"+ e.getMessage(),e);
        } finally {
            LdapUtils.close(ctx);
        }

         return false;


    }

    @Override
    public boolean modify(X509Server x509Server) throws Exception {

        if (x509Server == null || x509Server.getDn() == null|| x509Server.getDn().length() <= 0) {
            return false;
        }
        List<ModificationItem> mList = new ArrayList<ModificationItem>();
        if(x509Server.getServerIp()!=null&&x509Server.getServerIp().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getServerIpAttr(),x509Server.getServerIp())));
        if(x509Server.getOrgCode()!=null&&x509Server.getOrgCode().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getOrgcodeAttr(),x509Server.getOrgCode())));
        if(x509Server.getPwd()!=null&&x509Server.getPwd().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getPwdAttr(),x509Server.getPwd())));
        if(x509Server.getCertStatus()!=null&&x509Server.getCertStatus().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getCertStatusAttr(),x509Server.getCertStatus())));
        if(x509Server.getSerial()!=null&&x509Server.getSerial().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getSerialAttr(),x509Server.getSerial())));
        if(x509Server.getKey()!=null&&x509Server.getKey().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getKeyAttr(),x509Server.getKey())));
        if(x509Server.getCreateDate()!=null&&x509Server.getCreateDate().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getCreateDateAttr(),x509Server.getCreateDate())));
        if(x509Server.getEndDate()!=null&&x509Server.getEndDate().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getEndDateAttr(),x509Server.getEndDate())));
        if(x509Server.getIssueCa()!=null&&x509Server.getIssueCa().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getIssueCaAttr(),x509Server.getIssueCa())));
        if(x509Server.getCertType()!=null&&x509Server.getCertType().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getCertTypeAttr(),x509Server.getCertType())));
        if(x509Server.getKeyLength()!=null&&x509Server.getKeyLength().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getKeyLengthAttr(),x509Server.getKeyLength())));
        if(x509Server.getValidity()!=null&&x509Server.getValidity().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getValidityAttr(),x509Server.getValidity())));
        if(x509Server.getProvince()!=null&&x509Server.getProvince().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getProvinceAttr(),x509Server.getProvince())));
        if(x509Server.getCity()!=null&&x509Server.getCity().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getCityAttr(),x509Server.getCity())));
        if(x509Server.getOrganization()!=null&&x509Server.getOrganization().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getOrganizationAttr(),x509Server.getOrganization())));
        if(x509Server.getInstitution()!=null&&x509Server.getInstitution().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getInstitutionAttr(),x509Server.getInstitution())));
        if(x509Server.getDesc()!=null&&x509Server.getDesc().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getDescAttr(),x509Server.getDesc())));
        if(x509Server.getCertBase64Code()!=null&&x509Server.getCertBase64Code().length()>0)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.getCertBase64CodeAttr(),x509Server.getCertBase64Code())));
        if(x509Server.getUserCertificateAttr()!=null)
            mList.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE,new BasicAttribute(X509Server.DEFAULT_userCertificateAttr,x509Server.getUserCertificateAttr())));

        if (mList.size() > 0) {
            ModificationItem[] mArray = new ModificationItem[mList.size()];
            for (int i = 0; i < mList.size(); i++) {
                mArray[i] = mList.get(i);
            }
            LdapUtils ldapUtils = new LdapUtils();
            DirContext ctx = ldapUtils.getCtx();
            try{
                ctx.modifyAttributes(x509Server.getDn(), mArray);
                return true;
            }catch (Exception e){
                log.info("修改设备实体::"+x509Server.getDn()+":出现错误:"+ e.getMessage(),e);
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
            log.info("删除设备实体::" + DN +":出现错误:"+e.getMessage(),e);
        } finally {
            LdapUtils.close(ctx);
        }
       return false;
    }

}
