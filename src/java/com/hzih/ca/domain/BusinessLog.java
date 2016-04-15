package com.hzih.ca.domain;

import java.util.Date;

/**
 * 业务审计表
 *
 * @hibernate.class table="business_log"
 */
public class BusinessLog {
    /**
     * @hibernate.id column="Id" generator-class="identity"
     *               type="java.lang.Long"
     */
    Long id;

    /**
     * 业务类型（文件同步、UDP代理、TCP代理、数据库同步）
     *
     * @hibernate.property column="business_type" type="java.lang.String"
     */
    String businessType;

    /**
     * 日志时间
     *
     * @hibernate.property column="log_time" type="java.util.Date"
     */
    Date logTime;

    /**
     * 日志等级
     */
    String level;

    /**
     * 业务名
     *
     * @hibernate.property column="business_name" type="java.lang.String"
     */
    String businessName;

    /**
     * 业务描述
     *
     * @hibernate.property column="business_desc" type="java.lang.String"
     */
    String businessDesc;

    /**
     * 审计量（数据库：条数 文件：文件尺寸大小 代理：字节数）
     *
     * @hibernate.property column="audit_count" type="java.lang.Integer"
     */
    int auditCount;

    /**
     * 源IP
     *
     * @hibernate.property column="source_ip" type="java.lang.String"
     */
    String sourceIp;

    /**
     * 源端口
     *
     * @hibernate.property column="source_dest" type="java.lang.String"
     */
    String sourcePort;

    /**
     * 目标IP
     *
     * @hibernate.property column="dest_ip" type="java.lang.String" length="30"
     */
    String destIp;

    /**
     * 目标端口
     *
     * @hibernate.property column="dest_port" type="java.lang.String"
     *
     */
    String destPort;

    /**
     * 源端数据库
     *
     * @hibernate.property column="source_jdbc" type="java.lang.String"
     *
     */
    String sourceJdbc;

    /**
     * 目标数据库
     *
     * @hibernate.property column="dest_jdbc" type="java.lang.String"
     *
     */
    String destJdbc;

    String plugin;

    String fileName;

    int jsonId;
    /**
     * 导出1;未导出0
     */
    int flag;

    public BusinessLog() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getBusinessType() {
        return businessType;
    }

    public void setBusinessType(String businessType) {
        this.businessType = businessType;
    }

    public Date getLogTime() {
        return logTime;
    }

    public void setLogTime(Date logTime) {
        this.logTime = logTime;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getBusinessName() {
        return businessName;
    }

    public void setBusinessName(String businessName) {
        this.businessName = businessName;
    }

    public String getBusinessDesc() {
        return businessDesc;
    }

    public void setBusinessDesc(String businessDesc) {
        this.businessDesc = businessDesc;
    }

    public int getAuditCount() {
        return auditCount;
    }

    public void setAuditCount(int auditCount) {
        this.auditCount = auditCount;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(String sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestIp() {
        return destIp;
    }

    public void setDestIp(String destIp) {
        this.destIp = destIp;
    }

    public String getDestPort() {
        return destPort;
    }

    public void setDestPort(String destPort) {
        this.destPort = destPort;
    }

    public String getSourceJdbc() {
        return sourceJdbc;
    }

    public void setSourceJdbc(String sourceJdbc) {
        this.sourceJdbc = sourceJdbc;
    }

    public String getDestJdbc() {
        return destJdbc;
    }

    public void setDestJdbc(String destJdbc) {
        this.destJdbc = destJdbc;
    }

    public String getPlugin() {
        return plugin;
    }

    public void setPlugin(String plugin) {
        this.plugin = plugin;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public int getJsonId() {
        return jsonId;
    }

    public void setJsonId(int jsonId) {
        this.jsonId = jsonId;
    }

    public int getFlag() {
        return flag;
    }

    public void setFlag(int flag) {
        this.flag = flag;
    }
}
