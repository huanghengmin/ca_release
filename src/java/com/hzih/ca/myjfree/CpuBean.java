package com.hzih.ca.myjfree;

import org.jfree.data.time.Hour;

/**
 * Created by IntelliJ IDEA.
 * User: cx
 * Date: 13-2-19
 * Time: 下午5:53
 * To change this template use File | Settings | File Templates.
 */
public class CpuBean {
    private int minute;
    private Hour hour;
    private double cpuNum;
    private long currentMillis;

    public CpuBean(int minute, Hour hour, double cpuNum, long currentMillis) {
        this.minute = minute;
        this.hour = hour;
        this.cpuNum = cpuNum;
        this.currentMillis = currentMillis;
    }

    public int getMinute() {
        return minute;
    }

    public void setMinute(int minute) {
        this.minute = minute;
    }

    public Hour getHour() {
        return hour;
    }

    public void setHour(Hour hour) {
        this.hour = hour;
    }

    public double getCpuNum() {
        return cpuNum;
    }

    public void setCpuNum(double cpuNum) {
        this.cpuNum = cpuNum;
    }

    public long getCurrentMillis() {
        return currentMillis;
    }

    public void setCurrentMillis(long currentMillis) {
        this.currentMillis = currentMillis;
    }
}
