package com.hzih.ca.myjfree;

import org.apache.log4j.Logger;
import org.jfree.data.time.Hour;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * Created by IntelliJ IDEA.
 * User: cx
 * Date: 13-4-14
 * Time: 下午3:03
 * To change this template use File | Settings | File Templates.
 */
public class RunMonitorLiuliangBean2List extends Thread{
    private Logger log = Logger.getLogger(RunMonitorLiuliangBean2List.class);

    @Override
    public void run() {
        while (true) {

            GregorianCalendar gc2 = new GregorianCalendar();
//            int year2 = gc2.get(Calendar.YEAR);
//            int month2 = gc2.get(Calendar.MONTH);
//            int day2 = gc2.get(Calendar.DATE);
//            int hour2 = gc2.get(Calendar.HOUR_OF_DAY);
            int miniute2 = gc2.get(Calendar.MINUTE);
            int second2 = gc2.get(Calendar.SECOND);

            if(MonitorInfoList.liuLiangBean2ListRX==null) {
                MonitorInfoList.liuLiangBean2ListRX = new ArrayList<LiuLiangBean2>();
                MonitorInfoList.liuLiangBean2ListTX = new ArrayList<LiuLiangBean2>();
            }
//            double rxNetFlow = new LinuxUtil().getRxBytesNum();
//            double txNetFlow = new LinuxUtil().getTxBytesNum();
//            double rxNetFlow = new ProcessUtil().getRX();
//            double txNetFlow = new ProcessUtil().getTX();
            double rxNetFlow = new ProcessUtil().getRX();
            double txNetFlow = new ProcessUtil().getTX();

            if(0== MonitorInfoList.liuLiangBean2ListRX.size()){
                MonitorInfoList.liuLiangBean2ListRX.add(new LiuLiangBean2(second2,miniute2,new Hour(),rxNetFlow,0.0,System.currentTimeMillis()));
                MonitorInfoList.liuLiangBean2ListTX.add(new LiuLiangBean2(second2,miniute2,new Hour(),txNetFlow,0.0,System.currentTimeMillis()));
            }else {
                MonitorInfoList.liuLiangBean2ListRX.add(new LiuLiangBean2(second2,miniute2,new Hour(),rxNetFlow,(rxNetFlow- MonitorInfoList.liuLiangBean2ListRX.get(MonitorInfoList.liuLiangBean2ListRX.size()-1).getNetFlow())/10,System.currentTimeMillis()));
                MonitorInfoList.liuLiangBean2ListTX.add(new LiuLiangBean2(second2,miniute2,new Hour(),txNetFlow,(txNetFlow- MonitorInfoList.liuLiangBean2ListTX.get(MonitorInfoList.liuLiangBean2ListTX.size()-1).getNetFlow())/10,System.currentTimeMillis()));
            }
            if(MonitorInfoList.liuLiangBean2ListRX.size()>1&&(MonitorInfoList.liuLiangBean2ListRX.get(MonitorInfoList.liuLiangBean2ListRX.size()-1).getCurrentMillis()- MonitorInfoList.liuLiangBean2ListRX.get(0).getCurrentMillis())>(1000*60*6)){
                MonitorInfoList.liuLiangBean2ListRX.remove(0);
            }
            if(MonitorInfoList.liuLiangBean2ListTX.size()>1&&(MonitorInfoList.liuLiangBean2ListTX.get(MonitorInfoList.liuLiangBean2ListTX.size()-1).getCurrentMillis()- MonitorInfoList.liuLiangBean2ListTX.get(0).getCurrentMillis())>(1000*60*6)){
                MonitorInfoList.liuLiangBean2ListTX.remove(0);
            }

            try {
                sleep(1000*10);
            } catch (InterruptedException e) {
                log.error(e.getMessage(),e);
            }
//            log.info("读取网络流量服务已启动!");
        }
    }
}
