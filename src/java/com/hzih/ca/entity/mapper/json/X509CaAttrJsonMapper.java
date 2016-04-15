package com.hzih.ca.entity.mapper.json;

import com.hzih.ca.domain.District;
import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.service.DistrictService;

import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-5-2
 * Time: 下午4:39
 * To change this template use File | Settings | File Templates.
 */
public class X509CaAttrJsonMapper {

    public static String mapJsonFromAttr(SearchResult sr) throws javax.naming.NamingException {
        SimpleDateFormat format = new SimpleDateFormat("yyyy年MM月dd日HH时mm分ss秒");
        StringBuilder model = null;
        if (sr != null) {
            Attributes attr = sr.getAttributes();
            if (attr != null) {
                model = new StringBuilder();

                model.append("{");
                model.append(X509Ca.getDnAttr() + ":'" + sr.getNameInNamespace() + "'");

                if (attr.get(X509Ca.getCnAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getCnAttr() + ":'" + (String) attr.get(X509Ca.getCnAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getOrgcodeAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getOrgcodeAttr() + ":'" + (String) attr.get(X509Ca.getOrgcodeAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getPwdAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getPwdAttr() + ":'" + (String) attr.get(X509Ca.getPwdAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getCertStatusAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getCertStatusAttr() + ":'" + (String) attr.get(X509Ca.getCertStatusAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getSerialAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getSerialAttr() + ":'" + (String) attr.get(X509Ca.getSerialAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getCreateDateAttr()) != null) {
                    model.append(",");
                   String createDate =  (String) attr.get(X509Ca.getCreateDateAttr()).get();
                    model.append(X509Ca.getCreateDateAttr() + ":'" +  format.format(new Date(Long.parseLong(createDate))) + "'");
                }
                if (attr.get(X509Ca.getEndDateAttr()) != null) {
                    model.append(",");
                    String endDate =  (String) attr.get(X509Ca.getEndDateAttr()).get();
                    model.append(X509Ca.getEndDateAttr() + ":'" + format.format(new Date(Long.parseLong(endDate))) + "'");
                }
                if (attr.get(X509Ca.getIssueCaAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getIssueCaAttr() + ":'" + (String) attr.get(X509Ca.getIssueCaAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getCertTypeAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getCertTypeAttr() + ":'" + (String) attr.get(X509Ca.getCertTypeAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getKeyLengthAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getKeyLengthAttr() + ":'" + (String) attr.get(X509Ca.getKeyLengthAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getValidityAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getValidityAttr() + ":'" + (String) attr.get(X509Ca.getValidityAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getProvinceAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getProvinceAttr() + ":'" +(String) attr.get(X509Ca.getProvinceAttr()).get()  + "'");
                }
                if (attr.get(X509Ca.getCityAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getCityAttr() + ":'" +(String) attr.get( X509Ca.getCityAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getOrganizationAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getOrganizationAttr() + ":'" + (String) attr.get(X509Ca.getOrganizationAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getInstitutionAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getInstitutionAttr() + ":'" + (String) attr.get(X509Ca.getInstitutionAttr()).get() + "'");
                }
                if (attr.get(X509Ca.getDescAttr()) != null) {
                    model.append(",");
                    model.append(X509Ca.getDescAttr() + ":'" + (String) attr.get(X509Ca.getDescAttr()).get() + "'");
                }
                model.append("}");
            }
        }
        return model.toString();
    }

}
