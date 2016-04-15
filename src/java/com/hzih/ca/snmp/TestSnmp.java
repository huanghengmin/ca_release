package com.hzih.ca.snmp;

import org.opengoss.snmphibernate.api.ISnmpClientFacade;
import org.opengoss.snmphibernate.api.ISnmpSession;
import org.opengoss.snmphibernate.api.ISnmpSessionFactory;
import org.opengoss.snmphibernate.api.ISnmpTargetFactory;
import org.opengoss.snmphibernate.impl.snmp4j.Snmp4JClientFacade;
import org.opengoss.snmphibernate.mib.host.HrProcessorEntry;
import org.opengoss.snmphibernate.mib.host.HrStorageEntry;
import org.opengoss.snmphibernate.mib.rfc1213.TcpConnEntry;

import java.io.IOException;
import java.util.Iterator;

public class TestSnmp {


	public static void main(String arg[]) throws Exception {
//		ISnmpProcess test = new HostSnmpProcessV2Imp();
//		Equipment bean = new Equipment();
//		bean.setIp("192.168.2.3");
//		bean.setPort("161");
//        bean.setId(2);
//		test.init(bean, null);
//		test.run();

//        boolean isRun = false;
//        int deviceStatus = DeviceDataBean.I_Status_OK;
//        boolean isError = false;
        int deviceid;
        String devicename;
        ISnmpSession session = null;
        ISnmpClientFacade facade = new Snmp4JClientFacade();
        ISnmpSessionFactory sessionFactory = facade.getSnmpSessionFactory();
        ISnmpTargetFactory targetFactory = facade.getSnmpTargetFactory();
        String targetAddress = "";
        String ip = "127.0.0.1";
        try {
            session = sessionFactory.newSnmpSession(
                    targetFactory.newSnmpTarget(ip,161));
        } catch (NumberFormatException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        targetAddress = ip + "/" + 161;
        session.setRetries(2);
        session.setTimeout(1500);

        deviceid = 2;
        devicename = "test";
//        equipment = equ;

        int conncount = 0;
        int cpuuse = 0;
        int cpuindex = 0;
        long disktotal = 0;
        long diskuse = 0;
        long mem = 0;
        long memuse = 0;
        int diskunitsize = 0;
        int memunitsize = 0;
        Iterator<HrStorageEntry> storageit = null;
        Iterator<HrProcessorEntry> processit=null;
        if (!session.getTable(HrStorageEntry.class).isEmpty()) {
            storageit = session.getTable(HrStorageEntry.class).listIterator();
        } else {
            throw new Exception();
        }
        if(!session.getTable(HrProcessorEntry.class).isEmpty())
            processit = session.getTable(
                    HrProcessorEntry.class).listIterator();
        else{
            throw new Exception();

        }

        Iterator<TcpConnEntry> tcpconnit = null;
        if(!session.getTable(TcpConnEntry.class).isEmpty())
            tcpconnit=session.getTable(TcpConnEntry.class).listIterator();
        else{
            throw new Exception();
        }
        // disk mem
        while (storageit.hasNext()) {
            HrStorageEntry storage = storageit.next();
            if (storage.isDisk()) {
                disktotal = disktotal + (storage.getHrStorageSize());
                diskuse = diskuse + (storage.getHrStorageUsed());
                if (diskunitsize < storage.getHrStorageAllocationUnits())
                    diskunitsize = storage.getHrStorageAllocationUnits();
            }
            if (storage.isRam()) {
                mem = mem + (storage.getHrStorageSize());
                memuse = memuse + (storage.getHrStorageUsed());
                if (memunitsize < storage.getHrStorageAllocationUnits())
                    memunitsize = storage.getHrStorageAllocationUnits();
            }
        }
        // cpu use
        while (processit.hasNext()) {
            HrProcessorEntry process = processit.next();
            cpuuse = cpuuse + process.getHrProcessorLoad();
            cpuindex++;
        }
        if (cpuindex > 0)
            cpuuse = cpuuse / cpuindex;
        else{
            cpuuse= (int) ((Math.random())*20);
        }
        if(mem==0){

        }
        if(memuse==0){

        }
        // tcpconnect;
        while (tcpconnit.hasNext()) {
            TcpConnEntry tcp = tcpconnit.next();
            if (tcp.getTcpConnState() > 0) {
                conncount++;
            }
        }
        disktotal = (disktotal * diskunitsize) / (1000 * 1000 * 1000);
        diskuse = (diskuse * diskunitsize) / (1000 * 1000 * 1000);
        mem = (mem * memunitsize) / (1000 * 1000 * 1000);
        memuse = (memuse * memunitsize) / (1000 * 1000 * 1000);
//        DeviceDataBean bean = SnmpMonitorService.dataset.getDeviceDataBeanByID(devicename);
//        //DeviceDataBean entity = new DeviceDataBean();
//        bean.setCpu(cpuuse);
//        bean.setCurrentcon(conncount);
//        bean.setMem_total(mem);
//        if (memuse >= 0 && mem > 0)
//            bean.setMem(memuse);
//        else {
//            bean.setMem((float) 0);
//        }
//        bean.setDisk_total(disktotal);
//        if (diskuse >= 0 && disktotal > 0) {
//            bean.setDisk(diskuse);
//        } else {
//            bean.setDisk((float) 0);
//        }
//        System.out.println(cpuuse+"   "+diskuse+"   "+mem);
//        System.out.println("conncount:"+conncount);
//        System.out.println("cpuuse:"+cpuuse);
//        System.out.println("cpuindex:"+cpuindex);
//        System.out.println("disktotal:"+disktotal);
//        System.out.println("conncount:"+conncount);
//        System.out.println("mem:"+mem);
//        System.out.println("memuse:"+memuse);
//        System.out.println("diskunitsize:"+diskunitsize);
//        System.out.println("memunitsize:"+memunitsize);
//        deviceStatus = DeviceDataBean.I_Status_OK;
//        bean.setStatus(deviceStatus);
//        SnmpMonitorService.dataset.returnDeviceDataBean(devicename, bean);
////		log.info(entity.toJsonString());
//        EquipmentAlertDao dao = new EquipmentAlertDao();
//        EquipmentAlert alert = dao.findById(deviceid);
//        if((double)memuse/(double)mem * 100  > alert.getMemory()
//                || (double)diskuse/(double)disktotal * 100 > alert.getDisk()
//                || bean.getCpu() > alert.getCpu() ){
////            Service.alert.process(AlarmService.AlertType_Equipment, getAlertDataBean());
////            Service.alert.process(AlarmService.AlertType_Security, getAlertDataBean());
//            SysLogSend.sysLog(bean.toJsonString());
//        }
	}

}
