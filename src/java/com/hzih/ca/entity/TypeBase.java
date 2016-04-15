package com.hzih.ca.entity;

public class TypeBase {
	private boolean privated;
	private String appName;
	private String appDesc;
	private String appType;
	private String channel;
	private String channelport;
	private String plugin;
	private String dataPath;
	private boolean isActive;
	private boolean isAllow;
	private boolean deleteFile;
	private boolean local;
	private boolean recover;
	public boolean isFilter;
	public boolean isVirusScan;
    private int infoLevel;

    public boolean getPrivated() {
        return privated;
    }

    public void setPrivated(boolean privated) {
        this.privated = privated;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getAppDesc() {
        return appDesc;
    }

    public void setAppDesc(String appDesc) {
        this.appDesc = appDesc;
    }

    public String getAppType() {
        return appType;
    }

    public void setAppType(String appType) {
        this.appType = appType;
    }

    public String getChannel() {
        return channel;
    }

    public void setChannel(String channel) {
        this.channel = channel;
    }

    public String getChannelport() {
        return channelport;
    }

    public void setChannelport(String channelport) {
        this.channelport = channelport;
    }

    public String getPlugin() {
        return plugin;
    }

    public void setPlugin(String plugin) {
        this.plugin = plugin;
    }

    public String getDataPath() {
        return dataPath;
    }

    public void setDataPath(String dataPath) {
        this.dataPath = dataPath;
    }

    public boolean getActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public boolean getAllow() {
        return isAllow;
    }

    public void setAllow(boolean allow) {
        isAllow = allow;
    }

    public boolean getDeleteFile() {
        return deleteFile;
    }

    public void setDeleteFile(boolean deleteFile) {
        this.deleteFile = deleteFile;
    }

    public boolean getLocal() {
        return local;
    }

    public void setLocal(boolean local) {
        this.local = local;
    }

    public boolean getRecover() {
        return recover;
    }

    public void setRecover(boolean recover) {
        this.recover = recover;
    }

    public boolean isFilter() {
        return isFilter;
    }

    public void setFilter(boolean filter) {
        isFilter = filter;
    }

    public boolean isVirusScan() {
        return isVirusScan;
    }

    public void setVirusScan(boolean virusScan) {
        isVirusScan = virusScan;
    }

    public int getInfoLevel() {
        return infoLevel;
    }

    public void setInfoLevel(int infoLevel) {
        this.infoLevel = infoLevel;
    }
}
