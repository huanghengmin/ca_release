package com.hzih.ca.web.action.ldap;

import com.hzih.ca.utils.X509Context;
import org.apache.log4j.Logger;
import org.dom4j.*;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import java.io.*;

public class LdapXMLUtils {
    private static Logger logger = Logger.getLogger(LdapXMLUtils.class);
    public static final String ldap = "ldap";
    public static final String host = "host";
    public static final String port = "port";
    public static final String adm = "adm";
    public static final String pwd = "pwd";
    public static final String base = "base";
    public static final String charset = "utf-8";


    /**
     * @param name
     * @return
     */
    public static String getValue(String name) {
        SAXReader saxReader = new SAXReader();
        Document doc = null;
        String result = null;
        try {
            doc = saxReader.read(new File(X509Context.ldap_xml));
        } catch (DocumentException e) {
            e.printStackTrace();
        }
        if(doc!=null){
            Element ldap = doc.getRootElement();
            Element el = ldap.element(name);
            result = el.getText();
        }
        return result;
    }
    /**
     * @param host
     * @param port
     * @param adm
     * @param pwd
     */
    public static boolean save(String host, int port, String adm, String pwd, String base) {
        boolean flag = false;
        Document doc = DocumentHelper.createDocument();
        Element ldap = doc.addElement(LdapXMLUtils.ldap);
        Element host_el = ldap.addElement(LdapXMLUtils.host);
        host_el.addText(host);
        Element port_el = ldap.addElement(LdapXMLUtils.port);
        port_el.addText(String.valueOf(port));
        Element adm_el = ldap.addElement(LdapXMLUtils.adm);
        adm_el.addText(adm);
        Element pwd_el = ldap.addElement(LdapXMLUtils.pwd);
        pwd_el.addText(pwd);
        Element base_el = ldap.addElement(LdapXMLUtils.base);
        base_el.addText(base);
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setEncoding(charset);
        format.setIndent(true);
        try {
            XMLWriter xmlWriter = new XMLWriter(new FileOutputStream(new File(X509Context.ldap_xml)), format);
            try {
                xmlWriter.write(doc);
                flag = true;
            } catch (IOException e) {
                logger.error(e.getMessage(),e);
            } finally {
                try {
                    xmlWriter.flush();
                    xmlWriter.close();
                } catch (IOException e) {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }
            }
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage(), e);
        } catch (FileNotFoundException e) {
            logger.error(e.getMessage(),e);
        }
        return flag;
    }
}


