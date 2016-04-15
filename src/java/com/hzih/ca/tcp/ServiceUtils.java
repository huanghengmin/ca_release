package com.hzih.ca.tcp;

import com.hzih.ca.utils.StringContext;
import org.apache.log4j.Logger;

import java.io.*;
import java.util.Properties;


/**
 * Created by Administrator on 15-6-17.
 */
public class ServiceUtils {
    private final static Logger logger = Logger.getLogger(ServiceUtils.class);
    //设备ID号
    public String deviceId;

    private ServiceUtils() {

    }

    public static ServiceUtils getService() {
        Properties pros = new Properties();
        try {
            FileInputStream ins = new FileInputStream(StringContext.config_properties);
            pros.load(ins);
            ServiceUtils service = new ServiceUtils();
            service.deviceId = pros.getProperty("deviceId");
            return service;
        } catch (IOException e) {
            logger.error("加载配置文件config.properties错误", e);
            return null;
        }
    }
}
