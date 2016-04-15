package com.hzih.ca.utils;

/**
 * Created by IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-6-7
 * Time: 上午10:56
 * To change this template use File | Settings | File Templates.
 */
public class StringContext {
    public final static String serviceName = "ca" ;
    public final static String systemPath = System.getProperty("ca.home");
    public final static String INTERFACE = "/etc/network/interfaces";//linux下IP信息存储文件
    public final static String IFSTATE = "/etc/network/run/ifstate"; //linux下DNS信息
    public final static String localLogPath = systemPath + "/logs";   //日志文件目录
    public final static String webPath = systemPath+"/tomcat/webapps"; //war服务文件存储目录
    public final static String tempPath = systemPath+"/tomcat/temp"; //缓存目录
    public static final String SECURITY_CONFIG = StringContext.systemPath +"/tomcat/conf/server.xml";
    public final static String INTERNALXML = systemPath+"/repository/config.xml";//可信端配置文件
    public final static String EXTERNALXML = systemPath+"/repository/external/config.xml"; //非可信配置文件
    public final static String INTERNAL = "internal";  //可信
    public final static String EXTERNAL = "external";  //非可信
    public static final String config_properties  =  StringContext.systemPath + "/config/config.properties";

}
