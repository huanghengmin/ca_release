package com.hzih.ca.constant;

/**
 * 程序常量、静态变量
 * 
 * @author xiangqi
 * 
 */
public class AppConstant {
	/** * */
	public final static int PAGERESULT_PAGE_LENGTH = 15;

	/** 日志等级 * */
	public final static String SYSLOG_LEVEL_ERROR = "ERROR";
	public final static String SYSLOG_LEVEL_WARN = "WARN";
	public final static String SYSLOG_LEVEL_INFO = "INFO";
	public final static String SYSLOG_LEVEL_DEBUG = "DEBUG";

	/** 报警设置xml * */
	public final static String XML_ALERT_CONFIG_PATH = "WEB-INF/pages/xml/alert-sysConfig.xml";

	/** 数据库配置 */
	public final static String XML_DB_CONFIG_PATH = "WEB-INF/pages/xml/db-sysConfig.xml";

	/** 审计备份策略 */
	public static final String BACKUP_CONFIG_PATH = "WEB-INF/pages/xml/backup-sysConfig.xml";

}
