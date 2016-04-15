package com.hzih.ca.web.utils;

import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;

import java.io.File;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 12-11-8
 * Time: 下午11:25
 * To change this template use File | Settings | File Templates.
 */
public class DirectoryUtils {

    /**
     *
     * @param DN
     * @return
     */
    public static String[] getDNSplit(String DN){
        //得到不区分目录的DN
        String[] paths = null;
        if(DN.contains(",")){
            paths= DN.split(",");
        }else {
            paths = new String[]{DN};
        }
        return paths;
    }

    /**
     * 得到上级 DN
     * @param DN
     * @return
     */
    public static String getDNSuper(String DN){
        String  superNodeDN = null;
        if(DN.contains(",")){
            superNodeDN= DN.substring(DN.indexOf(",")+1,DN.length());
        }
        return superNodeDN;
    }

    /**
     *
     * @param DN
     * @return
     */
    public static String getCNForDN(String DN){
        String  superNodeDN = null;
        if(DN.contains(",")){
            superNodeDN= DN.substring(0,DN.indexOf(","));
            if(superNodeDN.contains("=")){
                superNodeDN = superNodeDN.substring(superNodeDN.indexOf("=")+1,superNodeDN.length());
            }
        }
        return superNodeDN;
    }

    public static String getCNForCN(String CN){
        String  superNodeDN = null;
        if(CN.contains("=")){
            if(superNodeDN.contains("=")){
                superNodeDN = superNodeDN.substring(superNodeDN.indexOf("=")+1,superNodeDN.length());
            }
        }
        return superNodeDN;
    }



    /**
     * 得到DN 对应的liunx路径
     * @param DN
     * @return
     */
    public static String getDNDirectory(String DN){
        String[] ldapPath = getDNSplit(DN);
        String liunxPath  = getDirectory(ldapPath);
        return X509Context.store_path +"/"+ liunxPath.toString();
    }

    /**
     *
     * @param DN
     * @return
     */
    public static String getSuperDirectory(String DN) {
        String superDN = getDNSuper(DN);
        String[] superDNS = getDNSplit(superDN);
        StringBuilder sb = new StringBuilder();
        sb.append(X509Context.store_path +"/").append(getDirectory(superDNS));
        String json = sb.toString();
        if (!json.endsWith("/")){
             sb.append("/");
        }
        return sb.toString();
    }

    /**
     * 转换分离数组为liunx路径
     * @param ldapPath
     * @return
     */
    private static String getDirectory(String[] ldapPath) {
        String paths = new String();
        //dc=pkica
        String baseDn = LdapXMLUtils.getValue(LdapXMLUtils.base);    //默认放置结点
        //算出baseDN长度
        int base_len = 1;
        String[] baseDns = null;
        if(baseDn.contains(","))      {
         baseDns = baseDn.split(",");
            base_len = baseDns.length;
        }
        //算出实际DN长度
        int len_ldap = ldapPath.length;
        //cn=CA1,dc=pkica
        for (int i=(len_ldap-base_len-1);i >= 0;i--){
            if(i==0) {
                if(ldapPath[i].contains("="))
                    paths +=ldapPath[i].substring(ldapPath[i].indexOf("=")+1,ldapPath[i].length());
            }else{
                if(ldapPath[i].contains("="))
                    paths +=ldapPath[i].substring(ldapPath[i].indexOf("=")+1,ldapPath[i].length())+"/";
            }
        }
        return paths;
    }


    /**
     * 获取上级结点名称
     * @param superDn
     * @return
     */
    public static String getCNSuper(String superDn){
        String superNodeCN = null;
        if(superDn.contains(",")){
            superNodeCN = superDn.substring(0,superDn.indexOf(","));
            if(superNodeCN.contains("=")) {
                superNodeCN = superNodeCN.substring(superNodeCN.indexOf("=") + 1,superNodeCN.length());
            }
        }
        return superNodeCN;
    }

    /**
     * 根据实际路径获取上级结点路径
      * @param liunxPath
     * @return
     */
    public static String getSuperStoreDirectory(String liunxPath){
        String father_dir = null;
        if(liunxPath.contains("/")){
            father_dir =  liunxPath.substring(0,liunxPath.lastIndexOf("/"));
        }
        return father_dir;
    }


    /**
     * 清除目录下面生成的文件
     * @param CN
     * @param childPath
     */
    public static void delStoreFiles(String CN, String childPath) {

        File key = new File(childPath + "/" + CN + X509Context.keyName);
        if (key.exists()){
            boolean del = key.delete();
            if(!del){
                key.delete();
            }
        }
        File csr = new File(childPath + "/" + CN + X509Context.csrName);
        if (csr.exists()){
            boolean del = csr.delete();
            if(!del){
                csr.delete();
            }
        }
        File pfx = new File(childPath + "/" + CN + X509Context.pkcsName);
        if (pfx.exists()){
            boolean del = pfx.delete();
            if(!del){
                pfx.delete();
            }
        }
        File cnf = new File(childPath + "/" + CN + X509Context.config_type_certificate);
        if (cnf.exists()){
            boolean del = cnf.delete();
            if(!del){
                cnf.delete();
            }
        }
        File jks = new File(childPath + "/" + CN + X509Context.jksName);
        if (jks.exists()){
            boolean del = jks.delete();
            if(!del){
                jks.delete();
            }
        }

        File cer = new File(childPath + "/" + CN + X509Context.certName);
        if (cer.exists()){
            boolean del = cer.delete();
            if(!del){
                cer.delete();
            }
        }
    }
}
