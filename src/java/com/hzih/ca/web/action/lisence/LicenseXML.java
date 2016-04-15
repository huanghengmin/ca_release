package com.hzih.ca.web.action.lisence;

import com.hzih.ca.utils.X509Context;
import org.apache.log4j.Logger;
import org.dom4j.*;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import java.io.*;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-17
 * Time: 下午8:03
 * To change this template use File | Settings | File Templates.
 */
public class LicenseXML {

    private static Logger logger = Logger.getLogger(LicenseXML.class);
    public static final String license = "license";
    public static final String count = "count";


    /**
     * @param name
     * @return
     */
    public static String getValue(String name) {
        SAXReader saxReader = new SAXReader();
        Document doc = null;
        String result = null;
        try {
            doc = saxReader.read(new File(X509Context.license_xml));
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
     * @param license
     */
    public static boolean save(String license) {
        boolean flag = false;
        Document doc = DocumentHelper.createDocument();
        Element license_root = doc.addElement(LicenseXML.license);
        Element license_count = license_root.addElement(LicenseXML.count);
        license_count.addText(license);
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setEncoding(X509Context.charset);
        format.setIndent(true);
        try {
            XMLWriter xmlWriter = new XMLWriter(new FileOutputStream(new File(X509Context.license_xml)), format);
            try {
                xmlWriter.write(doc);
                flag = true;
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
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

    public static boolean readLicense(int num)throws Exception{
        String use = LicenseXML.getValue(LicenseXML.count);
        if(use!=null){
            int use_count = Integer.parseInt(use)+num;
            if(use_count<=X509Context.license_count){
                return true;
            }
        }else {
            return true;
        }
        return false;
    }

    public static void addLicense(int num)throws Exception{
        String use = LicenseXML.getValue(LicenseXML.count);
        if(use!=null){
            int use_count = Integer.parseInt(use)+num;
             save(String.valueOf(use_count));
        }else {
            save(String.valueOf(num));
        }
    }
}
