package com.hzih.ca.entity;

/**
 * Created by Administrator on 15-7-24.
 */
public class DownConfigResponse extends SipXml {
    private String timeService;
    private String ca;
    private String terminalMonitor;
    private String center;
    private String ovpnFileName;
    private long ovpnFileSize;
    private String ovpnFile;
    private String keyFileName;
    private long keyFileSize;
    private String keyFile;
    private String crtFileName;
    private long crtFileSize;
    private String crtFile;
    private String strategyFileName;
    private long strategyFileSize;
    private String strategyFile;
    private String result;
    private String vpn;

    public String getVpn() {
        return vpn;
    }

    public void setVpn(String vpn) {
        this.vpn = vpn;
    }

    public String getTimeService() {
        return timeService;
    }

    public void setTimeService(String timeService) {
        this.timeService = timeService;
    }

    public String getCa() {
        return ca;
    }

    public void setCa(String ca) {
        this.ca = ca;
    }

    public String getTerminalMonitor() {
        return terminalMonitor;
    }

    public void setTerminalMonitor(String terminalMonitor) {
        this.terminalMonitor = terminalMonitor;
    }

    public String getCenter() {
        return center;
    }

    public void setCenter(String center) {
        this.center = center;
    }

    public String getOvpnFileName() {
        return ovpnFileName;
    }

    public void setOvpnFileName(String ovpnFileName) {
        this.ovpnFileName = ovpnFileName;
    }

    public long getOvpnFileSize() {
        return ovpnFileSize;
    }

    public void setOvpnFileSize(long ovpnFileSize) {
        this.ovpnFileSize = ovpnFileSize;
    }

    public String getOvpnFile() {
        return ovpnFile;
    }

    public void setOvpnFile(String ovpnFile) {
        this.ovpnFile = ovpnFile;
    }

    public String getKeyFileName() {
        return keyFileName;
    }

    public void setKeyFileName(String keyFileName) {
        this.keyFileName = keyFileName;
    }

    public long getKeyFileSize() {
        return keyFileSize;
    }

    public void setKeyFileSize(long keyFileSize) {
        this.keyFileSize = keyFileSize;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public String getCrtFileName() {
        return crtFileName;
    }

    public void setCrtFileName(String crtFileName) {
        this.crtFileName = crtFileName;
    }

    public long getCrtFileSize() {
        return crtFileSize;
    }

    public void setCrtFileSize(long crtFileSize) {
        this.crtFileSize = crtFileSize;
    }

    public String getCrtFile() {
        return crtFile;
    }

    public void setCrtFile(String crtFile) {
        this.crtFile = crtFile;
    }

    public String getStrategyFileName() {
        return strategyFileName;
    }

    public void setStrategyFileName(String strategyFileName) {
        this.strategyFileName = strategyFileName;
    }

    public long getStrategyFileSize() {
        return strategyFileSize;
    }

    public void setStrategyFileSize(long strategyFileSize) {
        this.strategyFileSize = strategyFileSize;
    }

    public String getStrategyFile() {
        return strategyFile;
    }

    public void setStrategyFile(String strategyFile) {
        this.strategyFile = strategyFile;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String toString(){
        return "<?xml version=\"1.0\"?>\r\n\r\n" +
                "<Response>\r\n" +
                "<DeviceType>" + deviceType + "</DeviceType>\r\n" +
                "<DeviceID>" + deviceId + "</DeviceID>\r\n" +
                "<CmdType>" + SipType.DownConfig + "</CmdType>\r\n" +
                "<TimeService>" + timeService + "</TimeService>\r\n" +
                "<CA>" + ca + "</CA>\r\n" +
                "<VPN>" + vpn + "</VPN>\r\n" +
                "<TerminalMonitor>" + terminalMonitor + "</TerminalMonitor>\r\n" +
                "<Center>" + center + "</Center>\r\n" +
                "<OvpnFileName>" + ovpnFileName + "</OvpnFileName>\r\n" +
                "<OvpnFileSize>" + ovpnFileSize + "</OvpnFileSize>\r\n" +
                "<OvpnFile>" + ovpnFile + "</OvpnFile>\r\n" +
                "<KeyFileName>" + keyFileName + "</KeyFileName>\r\n" +
                "<KeyFileSize>" + keyFileSize + "</KeyFileSize>\r\n" +
                "<KeyFile>" + keyFile + "</KeyFile>\r\n" +
                "<CrtFileName>" + crtFileName + "</CrtFileName>\r\n" +
                "<CrtFileSize>" + crtFileSize + "</CrtFileSize>\r\n" +
                "<CrtFile>" + crtFile + "</CrtFile>\r\n" +
                "<StrategyFileName>" + strategyFileName + "</StrategyFileName>\r\n" +
                "<StrategyFileSize>" + strategyFileSize + "</StrategyFileSize>\r\n" +
                "<StrategyFile>" + strategyFile + "</StrategyFile>\r\n" +
                "<Result>" + result + "</Result>\r\n" +
                "</Response>";

    }
}
