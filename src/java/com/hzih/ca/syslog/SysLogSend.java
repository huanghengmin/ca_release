package com.hzih.ca.syslog;

import com.hzih.ca.crl.CrlListener;

/**
 * Created with IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-8-27
 * Time: 下午3:07
 * To change this template use File | Settings | File Templates.
 */
public class SysLogSend {

    private static final String charset = "utf-8";
    /**
     * 发送日志方法
     * @param msg
     */
    public static void sysLog(String msg) {
        if(CrlListener.sysLogService.isRunning()){
            CrlListener.sysLogService.sysLogSend(msg, charset);
        }
    }
}
