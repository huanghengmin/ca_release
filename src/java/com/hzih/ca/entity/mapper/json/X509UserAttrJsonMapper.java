package com.hzih.ca.entity.mapper.json;

import com.hzih.ca.domain.District;
import com.hzih.ca.entity.X509User;
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
public class X509UserAttrJsonMapper {

    public static String mapJsonFromAttr(SearchResult sr) throws javax.naming.NamingException {
        SimpleDateFormat format = new SimpleDateFormat("yyyy年MM月dd日HH时mm分ss秒");
        StringBuilder model = null;
        if (sr != null) {
            Attributes attr = sr.getAttributes();
            if (attr != null) {
                model = new StringBuilder();

                model.append("{");
                model.append(X509User.getDnAttr() + ":'" + sr.getNameInNamespace() + "'");

                if (attr.get(X509User.getCnAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getCnAttr() + ":'" + (String) attr.get(X509User.getCnAttr()).get() + "'");
                }

                if (attr.get(X509User.getIdCardAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getIdCardAttr() + ":'" + (String) attr.get(X509User.getIdCardAttr()).get() + "'");
                }
                if (attr.get(X509User.getPhoneAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getPhoneAttr() + ":'" + (String) attr.get(X509User.getPhoneAttr()).get() + "'");
                }
                if (attr.get(X509User.getAddressAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getAddressAttr() + ":'" + (String) attr.get(X509User.getAddressAttr()).get() + "'");
                }
                if (attr.get(X509User.getUserEmailAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getUserEmailAttr() + ":'" + (String) attr.get(X509User.getUserEmailAttr()).get() + "'");
                }
                if (attr.get(X509User.getEmployeeCodeAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getEmployeeCodeAttr() + ":'" + (String) attr.get(X509User.getEmployeeCodeAttr()).get() + "'");
                }
                if (attr.get(X509User.getOrgcodeAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getOrgcodeAttr() + ":'" + (String) attr.get(X509User.getOrgcodeAttr()).get() + "'");
                }
                if (attr.get(X509User.getPwdAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getPwdAttr() + ":'" + (String) attr.get(X509User.getPwdAttr()).get() + "'");
                }
                if (attr.get(X509User.getCertStatusAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getCertStatusAttr() + ":'" + (String) attr.get(X509User.getCertStatusAttr()).get() + "'");
                }
                if (attr.get(X509User.getSerialAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getSerialAttr() + ":'" + (String) attr.get(X509User.getSerialAttr()).get() + "'");
                }
                if (attr.get(X509User.getCreateDateAttr()) != null) {
                    model.append(",");
                    String createDate =  (String) attr.get(X509User.getCreateDateAttr()).get();
                    model.append(X509User.getCreateDateAttr() + ":'" +  format.format(new Date(Long.parseLong(createDate))) + "'");
                }
                if (attr.get(X509User.getEndDateAttr()) != null) {
                    model.append(",");
                    String endDate =  (String) attr.get(X509User.getEndDateAttr()).get();
                    model.append(X509User.getEndDateAttr() + ":'" + format.format(new Date(Long.parseLong(endDate))) + "'");
                }
                if (attr.get(X509User.getInstitutionAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getInstitutionAttr() + ":'" + (String) attr.get(X509User.getInstitutionAttr()).get() + "'");
                }
                if (attr.get(X509User.getCertTypeAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getCertTypeAttr() + ":'" + (String) attr.get(X509User.getCertTypeAttr()).get() + "'");
                }
                if (attr.get(X509User.getKeyLengthAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getKeyLengthAttr() + ":'" + (String) attr.get(X509User.getKeyLengthAttr()).get() + "'");
                }
                if (attr.get(X509User.getValidityAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getValidityAttr() + ":'" + (String) attr.get(X509User.getValidityAttr()).get() + "'");
                }
                if (attr.get(X509User.getProvinceAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getProvinceAttr() + ":'" + (String) attr.get( X509User.getProvinceAttr()).get()+ "'");
                }
                if (attr.get(X509User.getCityAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getCityAttr() + ":'" + (String) attr.get( X509User.getCityAttr()).get()+ "'");
                }
                if (attr.get(X509User.getOrganizationAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getOrganizationAttr() + ":'" + (String) attr.get(X509User.getOrganizationAttr()).get() + "'");
                }
                if (attr.get(X509User.getIssueCaAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getIssueCaAttr() + ":'" + (String) attr.get(X509User.getIssueCaAttr()).get() + "'");
                }
                if (attr.get(X509User.getDescAttr()) != null) {
                    model.append(",");
                    model.append(X509User.getDescAttr() + ":'" + (String) attr.get(X509User.getDescAttr()).get() + "'");
                }
                model.append("}");
            }
        }
        return model.toString();
    }
}
