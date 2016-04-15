package com.hzih.ca.entity;

/**
 * Created by IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 11-10-17
 * Time: 下午7:17
 * To change this template use File | Settings | File Templates.
 */
public class ChannelIChangeUtils {
    private String interval;
    private String memuse;
    private String cpuuse;
    private String gcinterval;
    private String recover;
    private String systemmeantime;
    private String virusscan;

    public String getInterval() {
        return interval;
    }

    public void setInterval(String interval) {
        this.interval = interval;
    }

    public String getMemuse() {
        return memuse;
    }

    public void setMemuse(String memuse) {
        this.memuse = memuse;
    }

    public String getCpuuse() {
        return cpuuse;
    }

    public void setCpuuse(String cpuuse) {
        this.cpuuse = cpuuse;
    }

    public String getGcinterval() {
        return gcinterval;
    }

    public void setGcinterval(String gcinterval) {
        this.gcinterval = gcinterval;
    }

    public String getRecover() {
        return recover;
    }

    public void setRecover(String recover) {
        this.recover = recover;
    }

    public String getSystemmeantime() {
        return systemmeantime;
    }

    public void setSystemmeantime(String systemmeantime) {
        this.systemmeantime = systemmeantime;
    }

    public String getVirusscan() {
        return virusscan;
    }

    public void setVirusscan(String virusscan) {
        this.virusscan = virusscan;
    }
}
