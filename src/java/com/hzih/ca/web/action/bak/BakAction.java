package com.hzih.ca.web.action.bak;

import com.hzih.ca.service.LogService;
import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.StringContext;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.inetec.common.util.OSInfo;
import com.inetec.common.util.Proc;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.util.Date;

/**
 * Created by Administrator on 14-7-21.
 */
public class BakAction {
    private Logger logger = Logger.getLogger(BakAction.class);
    private LogService logService;

    private File uploadFile;
    private String uploadFileFileName;
    private String uploadFileContentType;

    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public File getUploadFile() {
        return uploadFile;
    }

    public void setUploadFile(File uploadFile) {
        this.uploadFile = uploadFile;
    }

    public String getUploadFileFileName() {
        return uploadFileFileName;
    }

    public void setUploadFileFileName(String uploadFileFileName) {
        this.uploadFileFileName = uploadFileFileName;
    }

    public String getUploadFileContentType() {
        return uploadFileContentType;
    }

    public void setUploadFileContentType(String uploadFileContentType) {
        this.uploadFileContentType = uploadFileContentType;
    }

    public String bak()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        boolean flag = BakRestoreUtils.bak(StringContext.systemPath);
        if(flag){
            msg = "备份系统数据成功";
            json = "{success:true,msg:'"+msg+"'}";

            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统备份", msg);


        }else {
            msg = "备份系统数据失败";
            json = "{success:false,msg:'"+msg+"'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统备份", msg);

        }
        actionBase.actionEnd(response, json, result);
        return null;
    }


    /**
     * 重启服务
     * @throws InterruptedException
     * @throws com.inetec.common.exception.Ex
     */
    public void upgradeService() throws Exception {
        Proc proc;
        OSInfo osinfo = OSInfo.getOSInfo();
        if (osinfo.isWin()) {
            proc = new Proc();
            proc.exec("nircmd service upgrade "+ StringContext.serviceName);
        }
        if (osinfo.isLinux()) {
            proc = new Proc();
            proc.exec("service "+StringContext.serviceName+" upgrade");
        }
    }



    public String bakRestore()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        boolean flag = BakRestoreUtils.bakRestore(StringContext.systemPath);
        if(flag){
            msg = "还原系统数据成功,服务将重启......!";
            json = "{success:true,msg:'"+msg+"'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统备份", msg);
            upgradeService();
        }else {
            msg = "还原系统数据失败";
            json = "{success:false,msg:'"+msg+"'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统备份", msg);

        }
        actionBase.actionEnd(response, json, result);
        return null;
    }


    public String uploadBak()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result = actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        if(uploadFile!=null&&uploadFile.length()>0){
            String path = StringContext.systemPath;
            if(!path.endsWith(File.separator)) {
                path += File.separator;
            }
            FileUtil.copy(uploadFile,path+X509Context.bak_file);
            msg = "上传系统包成功";
            json = "{success:true,msg:'"+msg+"'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统备份", msg);
        } else {
            msg = "上传系统包出错";
            json = "{success:false,msg:'"+msg+"'}";
            logger.info("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            SysLogSend.sysLog("管理员" + SessionUtils.getAccount(request).getUserName() + ",操作时间:" + new Date() + ",操作信息:" + msg);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "系统备份", msg);

        }
        actionBase.actionEnd(response, json, result);
        return null;
    }
}
