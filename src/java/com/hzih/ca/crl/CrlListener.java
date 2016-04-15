package com.hzih.ca.crl;

import com.hzih.ca.syslog.SysLogSendService;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.Timer;

/**
 * crl定时生成监听
 */
public class CrlListener implements ServletContextListener {

    private Timer timer = null;
    /**
     * 运行状态
     */
    public static boolean isRunSysLog = false;

    /**
     * 线程类
     */
    public static SysLogSendService sysLogService = new SysLogSendService();

    @Override
    public void contextDestroyed(ServletContextEvent arg0) {
        timer.cancel();
    }

    /**
     * 运行syslog进程
     */
     public void startSysLog(){
         if (CrlListener.isRunSysLog) {
             return;
         }
         sysLogService.init();
         Thread thread = new Thread(sysLogService);
         thread.start();
         CrlListener.isRunSysLog = true;
     }

    @Override
    public void contextInitialized(ServletContextEvent arg0) {
        //启动日志接收线程
        startSysLog();
        //定时器
        timer = new Timer(true);
        //设置任务计划，启动和间隔时间

//        第二个参数"0"的意思是:(0就表示无延迟)
//         第三个参数"60*60*1000"的意思就是:
//        (单位是毫秒60*60*1000为一小时)
//        (单位是毫秒3*60*1000为三分钟)
//        第一次调用之后，从第二次开始每隔多长的时间调用一次 run() 方法。
         timer.schedule(new CrlTask(), 0, 1000 * 60*60*24);
    }
}
