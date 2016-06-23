package com.hzih.ca.web.action.ldap;

import com.hzih.ca.web.utils.DirectoryUtils;
import org.apache.log4j.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-13
 * Time: 下午2:27
 * To change this template use File | Settings | File Templates.
 */
public class LdapUtils {
    private static final Logger log = Logger.getLogger(LdapUtils.class);

    /**
     * 测试LDAP连接
     * @return
     */
    public boolean ldapConnections(String host,int port,String admin,String pwd){
        boolean flag = false ;
        Hashtable<String, String> env = null;
        env= new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://"+host+":"+port);
        env.put(Context.AUTHORITATIVE, "simple");
        env.put(Context.SECURITY_PRINCIPAL, admin);
        env.put(Context.SECURITY_CREDENTIALS,pwd);
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        DirContext ctx = null ;
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException e) {
            log.error(e.getMessage(),e);
            return false;
        }
        if(ctx!=null){
            flag = true;
            try {
                ctx.close();
            } catch (NamingException e) {
                log.error(e.getMessage(),e);
                log.info("LDAP 连通出错!" + e.toString());
                return false;
            }
        }
        return flag;
    }

    /**
     *
     * 初始化LDAP连通参数
     * @return
     */
    public  Hashtable<String, String>   init(){
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://"+LdapXMLUtils.getValue(LdapXMLUtils.host)+":"+LdapXMLUtils.getValue(LdapXMLUtils.port));
        env.put(Context.AUTHORITATIVE, "simple");
        env.put(Context.SECURITY_PRINCIPAL, LdapXMLUtils.getValue(LdapXMLUtils.adm));
        env.put(Context.SECURITY_CREDENTIALS, LdapXMLUtils.getValue(LdapXMLUtils.pwd));
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        return env;
    }

    /**
     * 得到LDAP连接
     * @return 目录对象
     */
    public DirContext getCtx() {
        Hashtable<String, String> env  =  init();
        DirContext ctx =null;
        // 参数为空
        if (env == null) {
            log.info("请配置LDAP连接参数!");
        } else {
            try {
                ctx = new InitialDirContext(env);
//                log.info("LDAP 连接开启!");
            } catch (NamingException e) {
                log.error(e.getMessage(),e);
                log.info("创建LDAP连接不成功!");
                e.printStackTrace();
            }
        }
        return ctx;
    }

    public LdapContext getLdapContext() {
        Hashtable<String, String> env  =  init();
        LdapContext ctx =null;
        // 参数为空
        if (env == null) {
            log.info("请配置LDAP连接参数!");
        } else {
            try {
                ctx = new InitialLdapContext(env, null);
//                log.info("LDAP 连接开启!");
            } catch (NamingException e) {
                log.error(e.getMessage(),e);
                log.info("创建LDAP连接不成功!");
                e.printStackTrace();
            }
        }
        return ctx;
    }

    /**
     * 关闭LDAP连接
     * @param ctx
     */
    public static void close(DirContext ctx) {
        try {
            if (ctx != null)
                ctx.close();
//                log.info("LDAP 连接关闭成功!");
        }
        catch (Exception ex) {
            log.error("LDAP 连接关闭出错!",ex);
            ex.printStackTrace();
        }
    }

    /**
     *
     * @param attrs 属性列表
     * @param name     属性名称
     * @return
     * @throws NamingException
     */
    public static String getAttrValue(Attributes attrs, String name) {
        String att = null ;
        Attribute attr = attrs.get(name);
        try{
            for (NamingEnumeration all = attr.getAll(); all.hasMoreElements();) {
                Object o = all.nextElement();
                att = o.toString();
            }
        }catch (Exception e) {
            log.error(e.getMessage(),e);
            return null;
        }
        return  att;
    }




    /**
     *
     * @param mode   查找模式.
     * @param filter 过滤条件
     * @param base   查找结点
     * @param ctx    连接对象.
     */
    public static boolean delNode(int mode, String base, String filter, DirContext ctx){
        boolean flag = true;
        SearchControls ct = new SearchControls();
        ct.setSearchScope(mode);
        Vector<SearchResult> delDns = new Vector<>();
        NamingEnumeration ne = null;
        try {
            ne = ctx.search(base, filter, ct);
            while (ne.hasMore()) {
                SearchResult sr = (SearchResult) ne.nextElement();
                delDns.add(sr);
            }
        } catch (NamingException e) {
           log.error(e.getMessage(),e);
        }
        for (int i = delDns.size() - 1; i >= 0; i--) {
            SearchResult sr = delDns.get(i);
            String dn = sr.getNameInNamespace();
            try {
                ctx.destroySubcontext(dn);
                log.info("删除结点:"+ dn+"成功!");
            } catch (NamingException e) {
                flag = false;
                log.info("删除结点:"+ dn+"出错!");
                log.error(e.getMessage(),e);
            }
        }
        return flag;
    }


    /**
     * 获取上级结点信息
     * @param dn
     * @return
     */
    public static SearchResult findSuperNode(String dn) {
        String superNode = DirectoryUtils.getDNSuper(dn);
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.OBJECT_SCOPE);
        NamingEnumeration results = null;
        try {
            String filter = "(objectclass=*)";
            results = context.search(superNode, filter, sc);
            if (results.hasMore()) {
                SearchResult sr = (SearchResult) results.next();
                return sr;
            }
        } catch (Exception e) {
            log.error(e.getMessage(),e);
            return null;
        } finally {
            LdapUtils.close(context);
        }
        return null;
    }

    /**
     * 获取当前结点信息
     * @param dn
     * @return
     */
    public static SearchResult findCurrentNode(String dn) {
        LdapUtils ldapUtils = new LdapUtils();
        DirContext context = ldapUtils.getCtx();
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.OBJECT_SCOPE);
        NamingEnumeration results = null;
        try {
            String filter = "(objectclass=*)";
            results = context.search(dn, filter, sc);
            if (results.hasMore()) {
                SearchResult sr = (SearchResult) results.next();
                return sr;
            }
        } catch (Exception e) {
            log.error(e.getMessage(),e);
            return null;
        } finally {
            LdapUtils.close(context);
        }
        return null;
    }
}
