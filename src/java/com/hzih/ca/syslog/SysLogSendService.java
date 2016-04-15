package com.hzih.ca.syslog;

import com.hzih.ca.entity.SysLogServer;
import com.hzih.ca.utils.X509Context;
import org.apache.log4j.Logger;
import org.productivity.java.syslog4j.Syslog;
import org.productivity.java.syslog4j.SyslogConfigIF;
import org.productivity.java.syslog4j.SyslogIF;
import org.productivity.java.syslog4j.impl.net.udp.UDPNetSyslogConfig;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-8-27
 * Time: 下午3:07
 * To change this template use File | Settings | File Templates.
 */
public class SysLogSendService implements Runnable{
    private static final Logger logger = Logger.getLogger(SysLogSendService.class);
    private List<SysLogServer> sysLogs = new ArrayList<SysLogServer>();
    public static String log;
    private String charset;
    private boolean isRunning = false;
    public void init(){
        SysLogConfigXML config = new SysLogConfigXML();
        this.sysLogs = config.findAll(X509Context.syslog_xml);
    }


    public void sysLogSend(String log,String charset) {
        this.log = log;
        this.charset = charset;
        work();
    }

    public void run(){
        isRunning = true;
        while (isRunning){
            work();
            try {
                Thread.sleep(1000*5);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void work() {
        if(log!=null){
            if(sysLogs!=null){
                int i = 0;
                for(SysLogServer ipPort : sysLogs){
                    SyslogConfigIF config = new UDPNetSyslogConfig();
                    config.setHost(ipPort.getHost());
                    config.setCharSet(charset);
                    config.setPort(ipPort.getPort());
                    int j = i++;
                    SyslogIF syLog;
                    try{
                        syLog = Syslog.getInstance(String.valueOf(j));
                    } catch (Exception e){
                        e.printStackTrace();
                        syLog = null;
                    }
                    if(syLog==null){
                        syLog = Syslog.createInstance(String.valueOf(j), config);
                    }
                    syLog.info(log);
                    syLog.flush();
                    syLog.shutdown();
                }
            }
            log = null;
        }
    }

    public boolean isRunning(){
        return isRunning;
    }

    public void start(){
        isRunning = true;
    }

    public void close(){
        isRunning = false;
    }

    public static String getLog() {
        return log;
    }

    public static void setLog(String log) {
        SysLogSendService.log = log;
    }
}
