package com.hzih.ca.entity.mapper.json;

import com.hzih.ca.domain.District;
import com.hzih.ca.entity.X509Server;
import com.hzih.ca.service.DistrictService;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-5-2
 * Time: 下午4:46
 * To change this template use File | Settings | File Templates.
 */
public class X509ServerAttrJsonMapper {

    public static String mapJsonFromAttr(SearchResult sr) throws javax.naming.NamingException {
        SimpleDateFormat format = new SimpleDateFormat("yyyy年MM月dd日HH时mm分ss秒");
        StringBuilder model = null;
        if (sr != null) {
            Attributes attr = sr.getAttributes();
            if (attr != null) {
                model = new StringBuilder();
                model.append("{");
                model.append(X509Server.getDnAttr() + ":'" + sr.getNameInNamespace() + "'");

                if (attr.get(X509Server.getCnAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getCnAttr() + ":'" + (String) attr.get(X509Server.getCnAttr()).get() + "'");
                }

                if (attr.get(X509Server.getServerIpAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getServerIpAttr() + ":'" + (String) attr.get(X509Server.getServerIpAttr()).get() + "'");
                }

                if (attr.get(X509Server.getOrgcodeAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getOrgcodeAttr() + ":'" + (String) attr.get(X509Server.getOrgcodeAttr()).get() + "'");
                }
                if (attr.get(X509Server.getPwdAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getPwdAttr() + ":'" + (String) attr.get(X509Server.getPwdAttr()).get() + "'");
                }
                if (attr.get(X509Server.getCertStatusAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getCertStatusAttr() + ":'" + (String) attr.get(X509Server.getCertStatusAttr()).get() + "'");
                }
                if (attr.get(X509Server.getSerialAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getSerialAttr() + ":'" + (String) attr.get(X509Server.getSerialAttr()).get() + "'");
                }
                if (attr.get(X509Server.getCreateDateAttr()) != null) {
                    model.append(",");
                    String createDate =  (String) attr.get(X509Server.getCreateDateAttr()).get();
                    model.append(X509Server.getCreateDateAttr() + ":'" +  format.format(new Date(Long.parseLong(createDate))) + "'");
                }
                if (attr.get(X509Server.getEndDateAttr()) != null) {
                    model.append(",");
                    String endDate =  (String) attr.get(X509Server.getEndDateAttr()).get();
                    model.append(X509Server.getEndDateAttr() + ":'" + format.format(new Date(Long.parseLong(endDate))) + "'");
                }
                if (attr.get(X509Server.getIssueCaAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getIssueCaAttr() + ":'" + (String) attr.get(X509Server.getIssueCaAttr()).get() + "'");
                }
                if (attr.get(X509Server.getCertTypeAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getCertTypeAttr() + ":'" + (String) attr.get(X509Server.getCertTypeAttr()).get() + "'");
                }
                if (attr.get(X509Server.getKeyLengthAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getKeyLengthAttr() + ":'" + (String) attr.get(X509Server.getKeyLengthAttr()).get() + "'");
                }
                if (attr.get(X509Server.getValidityAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getValidityAttr() + ":'" + (String) attr.get(X509Server.getValidityAttr()).get() + "'");
                }
                if (attr.get(X509Server.getProvinceAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getProvinceAttr() + ":'" + (String) attr.get( X509Server.getProvinceAttr()).get()+ "'");
                }
                if (attr.get(X509Server.getCityAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getCityAttr() + ":'" + (String) attr.get(X509Server.getCityAttr()).get() + "'");
                }
                if (attr.get(X509Server.getOrganizationAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getOrganizationAttr() + ":'" + (String) attr.get(X509Server.getOrganizationAttr()).get() + "'");
                }
                if (attr.get(X509Server.getInstitutionAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getInstitutionAttr() + ":'" + (String) attr.get(X509Server.getInstitutionAttr()).get() + "'");
                }
                if (attr.get(X509Server.getDescAttr()) != null) {
                    model.append(",");
                    model.append(X509Server.getDescAttr() + ":'" + (String) attr.get(X509Server.getDescAttr()).get() + "'");
                }
                model.append("}");
            }
        }
        return model.toString();
    }
}
