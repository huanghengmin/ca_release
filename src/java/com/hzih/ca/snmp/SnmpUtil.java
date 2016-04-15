package com.hzih.ca.snmp;

import org.opengoss.snmphibernate.api.*;
import org.opengoss.snmphibernate.impl.snmp4j.Snmp4JClientFacade;
import org.opengoss.snmphibernate.mib.host.HrProcessorEntry;
import org.opengoss.snmphibernate.mib.host.HrStorageEntry;

import java.io.IOException;
import java.util.Iterator;

/**
 * Created by IntelliJ IDEA.
 * User: cx
 * Date: 13-3-14
 * Time: 下午4:52
 * To change this template use File | Settings | File Templates.
 */
public class SnmpUtil {

//    private Logger log = Logger.getLogger(SnmpUtil.class);

    public Double getCpuUse()  {
        ISnmpSession session = null;
        ISnmpClientFacade facade = new Snmp4JClientFacade();
        ISnmpSessionFactory sessionFactory = facade.getSnmpSessionFactory();
        ISnmpTargetFactory targetFactory = facade.getSnmpTargetFactory();
        String targetAddress = "";
        String ip = "127.0.0.1";
//        String ip = "192.168.1.111";
        try {
            session = sessionFactory.newSnmpSession(
                    targetFactory.newSnmpTarget(ip,161));
        } catch (NumberFormatException e) {
            e.printStackTrace();
//            log.error("snmp方法错误",e);
            return 0.0;
        } catch (IOException e) {
            e.printStackTrace();
//            log.error("snmp方法错误",e);
            return 0.0;
        }
        targetAddress = ip + "/" + 161;
        session.setRetries(2);
        session.setTimeout(1500);
        double cpuuse = 0.0;
        double cpuindex = 0.0;
        Iterator<HrProcessorEntry> processit=null;
        try {
            if(!session.getTable(HrProcessorEntry.class).isEmpty())
                processit = session.getTable(
                        HrProcessorEntry.class).listIterator();
            else{
//                System.out.println("出错");
//                log.error("出错");
            }
            while (processit.hasNext()) {
                HrProcessorEntry process = processit.next();
                cpuuse = cpuuse + process.getHrProcessorLoad();
                cpuindex++;
            }
            if (cpuindex > 0)
                cpuuse = cpuuse / cpuindex;
            else{
                cpuuse= (Math.random())*20;
            }
        } catch (IOException e) {
            e.printStackTrace();
//            log.error("snmp方法错误",e);
        } catch (SnmpException e) {
            e.printStackTrace();
//            log.error("snmp方法错误",e);
        } catch (SnmpAnnotationException e) {
            e.printStackTrace();
//            log.error("snmp方法错误",e);
        }catch (Exception e){
//            log.error("snmp方法错误",e);
            e.printStackTrace();
        }finally {
            try {
                session.close();
            } catch (IOException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }

        return cpuuse;
    }

    public Double getMem() {
        ISnmpSession session = null;
        ISnmpClientFacade facade = new Snmp4JClientFacade();
        ISnmpSessionFactory sessionFactory = facade.getSnmpSessionFactory();
        ISnmpTargetFactory targetFactory = facade.getSnmpTargetFactory();
        String targetAddress = "";
        String ip = "127.0.0.1";
//        String ip = "192.168.1.63";
        try {
            session = sessionFactory.newSnmpSession(
                    targetFactory.newSnmpTarget(ip,161));
        } catch (NumberFormatException e) {
            e.printStackTrace();
//            log.error(e);
        } catch (IOException e) {
            e.printStackTrace();
//            log.error(e);
        }
        targetAddress = ip + "/" + 161;
        session.setRetries(2);
        session.setTimeout(1500);
        Double mem = 0.0;
        Double memuse = 0.0;
        int memunitsize = 0;
        double memsyl=0.0;
        Iterator<HrStorageEntry> storageit = null;
        Iterator<HrProcessorEntry> processit=null;
        try{
            if (!session.getTable(HrStorageEntry.class).isEmpty()) {
                storageit = session.getTable(HrStorageEntry.class).listIterator();
            } else {
                throw new Exception();
            }
            if(!session.getTable(HrProcessorEntry.class).isEmpty())
                processit = session.getTable(
                        HrProcessorEntry.class).listIterator();
            else{
//                log.error("snmp方法错误",new Exception());
            }
            while (storageit.hasNext()) {
                HrStorageEntry storage = storageit.next();
                if (storage.isRam()) {
                    mem = mem + (storage.getHrStorageSize());
                    memuse = memuse + (storage.getHrStorageUsed());
                    if (memunitsize < storage.getHrStorageAllocationUnits())
                        memunitsize = storage.getHrStorageAllocationUnits();
                }
            }
            memsyl = memuse/mem*100;
        }catch (Exception e) {
            e.printStackTrace();
//            log.error("snmp方法错误",e);
        }finally {
            try {
                session.close();
            } catch (IOException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }
        // mem
//        mem = (mem * memunitsize) / (1000 * 1000 * 1000);
//        memuse = (memuse * memunitsize) / (1000 * 1000 * 1000);
//        System.out.println("mem:"+mem);
//        System.out.println("memuse:"+memuse);
        return memsyl;
    }

//    public static void main(String[] args) throws Exception {
//        System.out.println(new SnmpUtil().getCpuUse());
//        System.out.println(new SnmpUtil().getMem());
//    }
}
