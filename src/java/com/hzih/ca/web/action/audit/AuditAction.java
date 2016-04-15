package com.hzih.ca.web.action.audit;

import cn.collin.commons.utils.DateUtils;
import com.hzih.ca.service.AuditService;
import com.hzih.ca.service.LogService;
import com.hzih.ca.utils.StringUtils;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-6-19
 * Time: 上午9:55
 * To change this template use File | Settings | File Templates.
 * 日志审计
 */
public class AuditAction extends ActionSupport{
    private static final Logger logger = Logger.getLogger(AuditAction.class);
    private LogService logService;
    private AuditService auditService;
    private int start;
    private int limit;

    public String selectUserAudit() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json =  "{'success':true,'total':0,'rows':[]}";
        try {
            String startDateStr = request.getParameter("startDate");
            String endDateStr = request.getParameter("endDate");
            String logLevel = request.getParameter("logLevel");
            String userName = request.getParameter("userName");
            Date startDate = StringUtils.isBlank(startDateStr) ? null : DateUtils
                    .parse(startDateStr, "yyyy-MM-dd");
            Date endDate = StringUtils.isBlank(endDateStr) ? null : DateUtils
                    .parse(endDateStr, "yyyy-MM-dd");

            json = auditService.selectUserAudit(start/limit+1, limit,startDate,endDate,logLevel,userName );
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户日志审计","用户读取用户日志审计信息成功 ");
        } catch (Exception e) {
            logger.error("用户日志审计", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "用户日志审计","用户读取用户日志审计信息失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 读取系统审计日志
     * @return
     * @throws Exception
     */
    public String selectOSAudit() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json =  "{success:true,total:0,rows:[]}";
        try {
            String startDateStr = request.getParameter("startDate");
            String endDateStr = request.getParameter("endDate");
            String logLevel = request.getParameter("logLevel");
            Date startDate = StringUtils.isBlank(startDateStr) ? null : DateUtils
                    .parse(startDateStr, "yyyy-MM-dd");
            Date endDate = StringUtils.isBlank(endDateStr) ? null : DateUtils
                    .parse(endDateStr, "yyyy-MM-dd");

            json = auditService.selectOSAudit(start/limit+1, limit,startDate,endDate,logLevel );
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统日志审计","用户读取系统日志审计信息成功 ");
        } catch (Exception e) {
            logger.error("系统日志审计", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "系统日志审计","用户读取系统日志审计信息失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }


    /**
     * 读取设备日志审计
     * @return
     * @throws Exception
     */
    public String selectEquipmentAudit() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json =  "{success:true,total:0,rows:[]}";
        try {
            String startDateStr = request.getParameter("startDate");
            String endDateStr = request.getParameter("endDate");
            String logLevel = request.getParameter("logLevel");
            String equipmentName = request.getParameter("equipmentName");
            Date startDate = StringUtils.isBlank(startDateStr) ? null : DateUtils
                    .parse(startDateStr, "yyyy-MM-dd");
            Date endDate = StringUtils.isBlank(endDateStr) ? null : DateUtils
                    .parse(endDateStr, "yyyy-MM-dd");
            json = auditService.selectEquipmentAudit(start/limit+1, limit,startDate,endDate,logLevel,equipmentName);
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备日志审计","用户读取设备日志审计信息成功 ");
        } catch (Exception e) {
            logger.error("设备日志审计", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "设备日志审计","用户读取设备日志审计信息失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 读取业务日志审计
     * @return
     * @throws Exception
     */
    public String selectBusinessAudit() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json =  null;
        try {
            String startDateStr = request.getParameter("startDate");
            String endDateStr = request.getParameter("endDate");
            String businessType = request.getParameter("businessType");
            String businessName = request.getParameter("businessName");
            Date startDate = StringUtils.isBlank(startDateStr) ? null : DateUtils.parse(startDateStr, "yyyy-MM-dd");
            Date endDate = StringUtils.isBlank(endDateStr) ? null : DateUtils.parse(endDateStr, "yyyy-MM-dd");
            json = auditService.selectBusinessAudit(start/limit+1, limit,startDate,endDate,businessType,businessName);
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备日志审计","用户读取业务日志审计信息成功 ");
        } catch (Exception e) {
            logger.error("业务日志审计", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "设备日志审计","用户读取业务日志审计信息失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }


    public String truncateEquipment() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String msg = null;
        try {
            String startDate = request.getParameter("startDate");
            String endDate = request.getParameter("endDate");
            String logLevel = request.getParameter("logLevel");
            String equipmentName = request.getParameter("equipmentName");
            auditService.deleteEquipment(startDate,endDate,logLevel,equipmentName);
            msg = "清空成功,点击[确定]返回列表!";
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "设备日志审计","用户清空设备日志审计信息成功 ");
        } catch (Exception e) {
            logger.error("设备日志审计", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "设备日志审计","用户清空设备日志审计信息失败 ");
            msg = "清空失败"+e.getMessage();
        }
        String json =  "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }


    public String truncateBusiness() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String msg = null;
        try {
            String startDate = request.getParameter("startDate");
            String endDate = request.getParameter("endDate");
            String businessType = request.getParameter("businessType");
            String businessName = request.getParameter("businessName");
            auditService.deleteBusiness(startDate,endDate,businessType,businessName);
            msg = "清空成功,点击[确定]返回列表!";
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "业务日志审计","用户清空设业务志审计信息成功 ");
        } catch (Exception e) {
            logger.error("业务日志审计", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "业务日志审计","用户清空业务日志审计信息失败 ");
            msg = "清空失败"+e.getMessage();
        }
        String json =  "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }



    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public void setAuditService(AuditService auditService) {
        this.auditService = auditService;
    }

    public int getStart() {
        return start;
    }

    public void setStart(int start) {
        this.start = start;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }
}
