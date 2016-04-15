package com.hzih.ca.web.action.bks;

import com.hzih.ca.web.utils.X509ShellUtils;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-4
 * Time: 上午9:37
 * To change this template use File | Settings | File Templates.
 */
public class BKS {
    public static boolean createBKS(String CN,int y,String superCN,String superDirectory){
       return X509ShellUtils.build_bks(CN,y,superCN,superDirectory);
    }
}
