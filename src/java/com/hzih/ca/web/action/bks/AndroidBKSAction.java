package com.hzih.ca.web.action.bks;

import com.hzih.ca.syslog.SysLogSend;
import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.X509Context;
import com.hzih.ca.web.action.ActionBase;
import com.hzih.ca.web.utils.DirectoryUtils;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.util.StringTokenizer;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 12-11-8
 * Time: 下午11:21
 * To change this template use File | Settings | File Templates.
 */
public class AndroidBKSAction extends ActionSupport {
    private static Logger log = Logger.getLogger(AndroidBKSAction.class);

    /**
     * 下载bks文件
     * @return
     * @throws Exception
     */
    public String downloadAndroidBks() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = "{success:false}";
        String DN = request.getParameter("DN");
        String CN = request.getParameter("CN");
        //得到文件路径
        String dir = DirectoryUtils.getSuperDirectory(DN);
        String name =  CN + X509Context.bksName;
        String subPath = dir + CN + X509Context.bksName;
        String Agent = request.getHeader("User-Agent");
        StringTokenizer st = new StringTokenizer(Agent,";");
        st.nextToken();
        //得到用户的浏览器名  IE  Firefox
        String userBrowser = st.nextToken();
        File file = new File(subPath);
        if(file.exists()){
            FileUtil.downType(response, name, userBrowser);
            response = FileUtil.copy(file, response);
            json = "{success:true}";
        } else {
            log.info("目录:"+dir+",不存在android BSK信任文件!下载出错!");
            SysLogSend.sysLog("目录:"+dir+",不存在android BSK信任文件!下载出错!");
        }
        actionBase.actionEnd(response,json,result);
        return null;
    }
}
