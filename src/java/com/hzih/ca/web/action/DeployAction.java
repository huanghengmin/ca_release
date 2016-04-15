package com.hzih.ca.web.action;

import com.hzih.ca.utils.StringContext;
import com.inetec.common.util.OSInfo;
import com.inetec.common.util.OSReBoot;
import com.inetec.common.util.OSShutDown;
import com.inetec.common.util.Proc;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 14-3-20
 * Time: 下午12:16
 * To change this template use File | Settings | File Templates.
 */
public class DeployAction extends ActionSupport{
    Logger logger = Logger.getLogger(DeployAction.class);

    /**
     * 设备重启
     * @return
     * @throws Exception
     */
    public String restart() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String msg = null;
        try {
            OSReBoot.exec();
            Thread.sleep(1000*6);
            msg = "重启设备成功";
        } catch (Exception e) {
            msg = "重启设备失败"+new Date();
            logger.error(msg,e);
        }
        String json = "{success:true,msg:'"+msg+"'}";
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }

    /**
     * 设备关闭
     * @return
     * @throws Exception
     */
    public String shutdown() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String msg = null;
        try {
            OSShutDown.exec();
            Thread.sleep(1000*3);
            msg = "关闭设备成功";
        } catch (Exception e) {
            e.printStackTrace();
            msg = "关闭设备失败";
        }
        String json = "{success:true,msg:'"+msg+"'}";
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }

    /**
     * 重启服务
     * @throws InterruptedException
     * @throws com.inetec.common.exception.Ex
     */
    public String upgradeService() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String msg = null;
        Proc proc;
        OSInfo osinfo = OSInfo.getOSInfo();
        if (osinfo.isWin()) {
            proc = new Proc();
            proc.exec("nircmd service upgrade "+StringContext.serviceName);
        }
        if (osinfo.isLinux()) {
            proc = new Proc();
            proc.exec("service "+StringContext.serviceName+" upgrade");
        }
        String json = "{success:true}";
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }

   /**
     * file 改名
     * @param oldFile
     * @param renameToFile
     */
    private void renameFile(File oldFile,File renameToFile) {
        oldFile.renameTo(renameToFile);
    }

    /**
     * 重新部署
     * @return
     * @throws Exception
     */
    public String deploy()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String msg = null;
        String json = null;
        File dir = new File(StringContext.webPath+"/ROOT.war_deploy");
        File old_war = new File(StringContext.webPath+"/ROOT.war");
        if(dir.exists()&&old_war.exists()){
            File deploy_bak = new File(StringContext.webPath+"/ROOT.war_ca");
            renameFile(old_war,deploy_bak);
            renameFile(dir,old_war);
//            reload_service("ca");
            msg = "重新部署系统,点击[确定]后重启系统!";
            json = "{success:true,msg:'"+msg+"'}";
        }else {
            msg = "重新部署出现错误,部署文件丢失!";
            json = "{success:false,msg:'"+msg+"'}";
        }

        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }




    /**
     * 转到访问web界面
     * @return
     * @throws Exception
     */
    public String admin()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String msg = null;
        File dir = new File(StringContext.webPath+"/ROOT.war_ca");
        File old_war = new File(StringContext.webPath+"/ROOT.war");
        if(dir.exists()&&old_war.exists()){
            File deploy_bak = new File(StringContext.webPath+"/ROOT.war_deploy");
            renameFile(old_war,deploy_bak);
            renameFile(dir,old_war);
//            reload_service("ca");
            msg = "转到系统访问界面成功,点击[确定]返回页面!";
        }else {
            msg = "转到系统访问界面失败,未找到系统数据包!";
        }
        String json = "{success:true,msg:'"+msg+"'}";
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }

}
