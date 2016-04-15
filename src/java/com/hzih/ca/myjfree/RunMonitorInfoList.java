package com.hzih.ca.myjfree;

import com.hzih.ca.snmp.SnmpUtil;
import org.apache.log4j.Logger;
import org.jfree.data.time.Hour;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * Created by IntelliJ IDEA.
 * User: cx
 * Date: 13-3-18
 * Time: 上午9:42
 * To change this template use File | Settings | File Templates.
 */
public class RunMonitorInfoList extends Thread{
    private Logger log = Logger.getLogger(RunMonitorInfoList.class);

    @Override
    public void run() {
        while (true) {
            GregorianCalendar gc2 = new GregorianCalendar();
//            int year2 = gc2.get(Calendar.YEAR);
//            int month2 = gc2.get(Calendar.MONTH);
//            int day2 = gc2.get(Calendar.DATE);
//            int hour2 = gc2.get(Calendar.HOUR_OF_DAY);
            int miniute2 = gc2.get(Calendar.MINUTE);

//            int second2 = gc2.get(Calendar.SECOND);
//            ArrayList<CpuBean> cpuBeanList = MonitorInfoList.cpuBeanList;
    //    String flagts = request.getParameter("flagts");
            try{
                if(MonitorInfoList.cpuBeanList==null) {
                    MonitorInfoList.cpuBeanList = new ArrayList<CpuBean>();
                }
                MonitorInfoList.cpuBeanList.add(new CpuBean( miniute2, new Hour(), new SnmpUtil().getCpuUse(), System.currentTimeMillis() ));
                if(MonitorInfoList.cpuBeanList.size()>1&&(MonitorInfoList.cpuBeanList.get(MonitorInfoList.cpuBeanList.size()-1).getCurrentMillis()- MonitorInfoList.cpuBeanList.get(0).getCurrentMillis())>(1000*60*60)){
                    MonitorInfoList.cpuBeanList.remove(0);
                }

                if(MonitorInfoList.cpuBeanListMem==null) {
                    MonitorInfoList.cpuBeanListMem = new ArrayList<CpuBean>();
                }
                MonitorInfoList.cpuBeanListMem.add(new CpuBean( miniute2, new Hour(), new SnmpUtil().getMem(), System.currentTimeMillis() ));
                if(MonitorInfoList.cpuBeanListMem.size()>1&&(MonitorInfoList.cpuBeanListMem.get(MonitorInfoList.cpuBeanListMem.size()-1).getCurrentMillis()- MonitorInfoList.cpuBeanListMem.get(0).getCurrentMillis())>(1000*60*60)){
                    MonitorInfoList.cpuBeanListMem.remove(0);
                }
            }catch (Exception e){
                log.error("系统监控服务启动失败！"+e.getMessage(),e);
            }
//            if(MonitorInfoList.liuLiangBeanListRX==null) {
//                MonitorInfoList.liuLiangBeanListRX = new ArrayList<LiuLiangBean>();
//                MonitorInfoList.liuLiangBeanListTX = new ArrayList<LiuLiangBean>();
//            }
////            double rxNetFlow = new LinuxUtil2().getRxBytesNum1();
////            double txNetFlow = new LinuxUtil2().getTxBytesNum1();
////            double rxNetFlow = new LinuxUtil().getRxBytesNum();
////            double txNetFlow = new LinuxUtil().getTxBytesNum();
//            double rxNetFlow = new ProcessUtil().getRX();
//            double txNetFlow = new ProcessUtil().getTX();
//
//            if(0==MonitorInfoList.liuLiangBeanListRX.size()){
//                MonitorInfoList.liuLiangBeanListRX.add(new LiuLiangBean(miniute2,new Hour(),rxNetFlow,0.0,System.currentTimeMillis()));
//                MonitorInfoList.liuLiangBeanListTX.add(new LiuLiangBean(miniute2,new Hour(),txNetFlow,0.0,System.currentTimeMillis()));
//            }else {
//                MonitorInfoList.liuLiangBeanListRX.add(new LiuLiangBean(miniute2,new Hour(),rxNetFlow,rxNetFlow-MonitorInfoList.liuLiangBeanListRX.get(MonitorInfoList.liuLiangBeanListRX.size()-1).getNetFlow(),System.currentTimeMillis()));
//                MonitorInfoList.liuLiangBeanListTX.add(new LiuLiangBean(miniute2,new Hour(),txNetFlow,txNetFlow-MonitorInfoList.liuLiangBeanListTX.get(MonitorInfoList.liuLiangBeanListTX.size()-1).getNetFlow(),System.currentTimeMillis()));
//            }
//            if(MonitorInfoList.liuLiangBeanListRX.size()>1&&(MonitorInfoList.liuLiangBeanListRX.get(MonitorInfoList.liuLiangBeanListRX.size()-1).getCurrentMillis()-MonitorInfoList.liuLiangBeanListRX.get(0).getCurrentMillis())>(1000*60*60)){
//                MonitorInfoList.liuLiangBeanListRX.remove(0);
//            }
//            if(MonitorInfoList.liuLiangBeanListTX.size()>1&&(MonitorInfoList.liuLiangBeanListTX.get(MonitorInfoList.liuLiangBeanListTX.size()-1).getCurrentMillis()-MonitorInfoList.liuLiangBeanListTX.get(0).getCurrentMillis())>(1000*60*60)){
//                MonitorInfoList.liuLiangBeanListTX.remove(0);
//            }
            try {
                sleep(1000*60);
            } catch (InterruptedException e) {
                log.error(e.getMessage(),e);
            }
//            log.info("系统监控服务已启动!");
        }
    }

    public static void main(String args[]) {
        new RunMonitorInfoList().start();
    }
}
