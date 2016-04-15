package com.hzih.ca.myjfree;

import org.jfree.data.time.Hour;

/**
 * Created by IntelliJ IDEA.
 * User: cx
 * Date: 13-2-19
 * Time: 下午5:48
 * To change this template use File | Settings | File Templates.
 */
public class LiuLiangBean {
    private int minute;
    private Hour hour;
    private double netFlow;
    private double liuliangNum;
    private long currentMillis;

    public LiuLiangBean() {
    }

    public LiuLiangBean(int minute, Hour hour, double netFlow, double liuliangNum, long currentMillis) {
        this.minute = minute;
        this.hour = hour;
        this.netFlow = netFlow;
        this.liuliangNum = liuliangNum;
        this.currentMillis = currentMillis;
    }

    public double getNetFlow() {
        return netFlow;
    }

    public void setNetFlow(double netFlow) {
        this.netFlow = netFlow;
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

    public double getLiuliangNum() {
        return liuliangNum;
    }

    public void setLiuliangNum(double liuliangNum) {
        this.liuliangNum = liuliangNum;
    }

    public long getCurrentMillis() {
        return currentMillis;
    }

    public void setCurrentMillis(long currentMillis) {
        this.currentMillis = currentMillis;
    }
}
