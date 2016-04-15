package com.hzih.ca.web.action.ldap;

import com.hzih.ca.entity.X509Ca;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-3
 * Time: 下午2:04
 * To change this template use File | Settings | File Templates.
 */
public class DNUtils {
    /**
     * 获取DN
     * @param superDN
     * @param cn
     * @return
     */
    public static String add(String superDN, String cn) {
        StringBuilder sb = new StringBuilder();
        sb.append(X509Ca.getCnAttr()).append("=").append(cn).append(",").append(superDN);
        return sb.toString();
    }
}
