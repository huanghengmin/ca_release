package com.hzih.ca.web.action.user;

import com.hzih.ca.domain.SafePolicy;
import com.hzih.ca.service.LogService;
import com.hzih.ca.service.SafePolicyService;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 12-6-11
 * Time: 上午9:47
 * To change this template use File | Settings | File Templates.
 */
public class SafePolicyAction extends ActionSupport{
    private static final Logger logger = Logger.getLogger(SafePolicyAction.class);
    private SafePolicy safePolicy;
    private LogService logService;
    private SafePolicyService safePolicyService;
//    private String remoteDisabled;
    private String macDisabled;

    public String select() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
		String json = null;
        try {
            json = safePolicyService.select();
//            logService.newLog("INFO",  SessionUtils.getAccount(request).getUserName(), "安全策略","用户获取安全策略信息成功");
        } catch (Exception e) {
            logger.error("安全策略", e);
            logService.newLog("ERROE", SessionUtils.getAccount(request).getUserName(), "安全策略","用户获取安全策略信息失败");
        }
        actionBase.actionEnd(response,json,result);
        return null;
    }

    public String selectPasswordRules() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
		String json = null;
        try {
            json = safePolicyService.selectPasswordRules();
//            logService.newLog("INFO",  SessionUtils.getAccount(request).getUserName(), "用户管理","用户获取安全策略密码规则信息成功");
        } catch (Exception e) {
            logger.error("用户管理", e);
            logService.newLog("ERROE", SessionUtils.getAccount(request).getUserName(), "用户管理","用户获取安全策略密码规则信息失败");
        }
        actionBase.actionEnd(response,json,result);
        return null;
    }

    public String update() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
		String msg = null;
        try {
//            if(remoteDisabled!=null){
//                if(remoteDisabled.equals("on")){
//                    safePolicy.setRemoteDisabled(true);
//                } else {
//                    safePolicy.setRemoteDisabled(false);
//                }
//            } else {
//                safePolicy.setRemoteDisabled(false);
//            }
            if(macDisabled!=null ){
                if( macDisabled.equals("on")){
                    safePolicy.setMacDisabled(true);
                } else {
                    safePolicy.setMacDisabled(false);
                }
            } else {
                safePolicy.setMacDisabled(false);
            }
            msg = safePolicyService.update(safePolicy);
            logService.newLog("INFO",  SessionUtils.getAccount(request).getUserName(), "安全策略","用户修改安全策略信息成功");
        } catch (Exception e) {
            logger.error("安全策略", e);
            logService.newLog("ERROE", SessionUtils.getAccount(request).getUserName(), "安全策略","用户修改安全策略信息失败");
            msg = "<font color=\"red\">修改失败</font>";
        }
        String json = "{success:true,msg:'"+msg+"'}";
        macDisabled = null;
//        remoteDisabled = null;
        actionBase.actionEnd(response,json,result);
        return null;
    }

    public SafePolicy getSafePolicy() {
        return safePolicy;
    }

    public void setSafePolicy(SafePolicy safePolicy) {
        this.safePolicy = safePolicy;
    }

    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public SafePolicyService getSafePolicyService() {
        return safePolicyService;
    }

    public void setSafePolicyService(SafePolicyService safePolicyService) {
        this.safePolicyService = safePolicyService;
    }

//    public String getRemoteDisabled() {
//        return remoteDisabled;
//    }
//
//    public void setRemoteDisabled(String remoteDisabled) {
//        this.remoteDisabled = remoteDisabled;
//    }

    public String getMacDisabled() {
        return macDisabled;
    }

    public void setMacDisabled(String macDisabled) {
        this.macDisabled = macDisabled;
    }
}
