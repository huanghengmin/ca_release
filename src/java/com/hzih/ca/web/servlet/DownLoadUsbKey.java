package com.hzih.ca.web.servlet;

import com.hzih.ca.utils.FileUtil;
import com.hzih.ca.utils.StringContext;
import com.hzih.ca.web.action.ActionBase;
import org.apache.log4j.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.StringTokenizer;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-4-3
 * Time: 下午5:43
 * To change this template use File | Settings | File Templates.
 */
public class DownLoadUsbKey extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Logger logger = Logger.getLogger(DownLoadUsbKey.class);

    public void init(ServletConfig config) throws ServletException
    {
        super.init(config);
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
//        ActionBase actionBase = new ActionBase();
//        String result = actionBase.actionBegin(request);
        String msg = null;
        String path = null;
        try{
            String Agent = request.getHeader("User-Agent");
            StringTokenizer st = new StringTokenizer(Agent,";");
            st.nextToken();
            String userBrowser = st.nextToken();
            path = StringContext.systemPath + "/csp/ZD-SM1-UK/ZD-SM1-User.exe";
            File source = new File(path);
            String name = source.getName();
            FileUtil.downType(response, name, userBrowser);
            response = FileUtil.copy(source, response);
            msg = "UsbKey驱动下载成功";
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "用户日志审计","用户日志下载成功 ");
        } catch (Exception e){
            e.printStackTrace();
            msg = "UsbKey驱动下载失败";
            logger.error("UsbKey驱动下载失败",e);
//            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "用户日志审计","用户日志下载失败 ");
        }
        String json = "{success:true,msg:'" + msg + "'}";
        PrintWriter writer = response.getWriter();
        writer.write(json);
        writer.flush();
        writer.close();
//        actionBase.actionEnd(response, json, result);
    }

    @Override
    public void destroy() {
        super.destroy();
    }
}
