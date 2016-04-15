package com.hzih.ca.web.action.ca;

import com.hzih.ca.entity.X509Ca;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ldap.DNUtils;
import com.hzih.ca.web.action.ldap.LdapXMLUtils;
import org.apache.log4j.Logger;
import org.dom4j.*;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import java.io.*;

public class X509CaXML {
    private static Logger logger = Logger.getLogger(X509CaXML.class);
    public static final String ca = "ca";
    public static final String cn = "cn";
    public static final String province = "province";
    public static final String city = "city";
    public static final String validity = "validity";
    public static final String keyLength = "keyLength";
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
            doc = saxReader.read(new File(X509Context.ca_xml));
        } catch (DocumentException e) {
            logger.error(e.getMessage(),e);
        }
        if(doc!=null){
            Element ldap = doc.getRootElement();
            Element el = ldap.element(name);
            result = el.getText();
        }
        return result;
    }

    /**
     *
     * @return
     */
    public static String getSignDn(){
        String cn = getValue(X509CaXML.cn);
        if(cn!=null){
            String base = LdapXMLUtils.getValue(LdapXMLUtils.base);
            if(base!=null)
                return DNUtils.add(base, cn);
            else
                return null;
        }
        return null;
    }


    /**
     * 保存
     * @param x509Ca
     * @return
     */
    public static boolean save(X509Ca x509Ca) {
        boolean flag = false;
        Document doc = DocumentHelper.createDocument();
        Element ca = doc.addElement(X509CaXML.ca);
        Element province_el = ca.addElement(X509CaXML.province);
        province_el.addText(x509Ca.getProvince());
        Element city_el = ca.addElement(X509CaXML.city);
        city_el.addText(x509Ca.getCity());
        Element validity_el = ca.addElement(X509CaXML.validity);
        validity_el.addText(x509Ca.getValidity());
        Element keyLength_el = ca.addElement(X509CaXML.keyLength);
        keyLength_el.addText(x509Ca.getKeyLength());
        Element cn_el = ca.addElement(X509CaXML.cn);
        cn_el.addText(x509Ca.getCn());
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setEncoding(charset);
        format.setIndent(true);
        try {
            XMLWriter xmlWriter = new XMLWriter(new FileOutputStream(new File(X509Context.ca_xml)), format);
            try {
                xmlWriter.write(doc);
                flag = true;
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
            }finally {
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


