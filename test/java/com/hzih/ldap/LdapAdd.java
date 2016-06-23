package com.hzih.ldap;

import com.hzih.ca.dao.X509CaDao;
import com.hzih.ca.dao.impl.X509CaDaoImpl;
import com.hzih.ca.entity.X509Ca;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * Created by Administrator on 16-6-21.
 */
public class LdapAdd {
    public static void main(String args[])throws Exception{
        Hashtable<String, String> env = null;
        env= new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:10389/");
        env.put(Context.AUTHORITATIVE, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS,"secret");

//        env.put(Context.PROVIDER_URL, "ldap://localhost:389/");
//        env.put(Context.SECURITY_PRINCIPAL,"cn=admin,dc=pkica");
//        env.put(Context.SECURITY_CREDENTIALS,"123456");
//        env.put(Context.SECURITY_AUTHENTICATION,"simple");

        env.put("com.sun.jndi.ldap.connect.pool", "true");
        DirContext ctx = null ;
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException e) {
            e.printStackTrace();
        }
        for (int i=0;i<50;i++) {
            X509Ca x509Ca = new X509Ca();
            x509Ca.setCn("StrategyCA"+i);
            x509Ca.setIssueCa("dc=example,dc=com");
//            x509Ca.setIssueCa("dc=pkica");
            X509CaDao x509CaDao = new X509CaDaoImpl();
            x509CaDao.add(ctx, x509Ca);
        }
    }
}
