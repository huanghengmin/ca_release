package com.hzih.ca.web.action.net;

import com.hzih.ca.entity.NetInfo;
import com.hzih.ca.service.LogService;
import com.hzih.ca.utils.GetListNetInfo;
import com.hzih.ca.utils.NetworkUtil;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.action.ActionBase;
import com.inetec.common.net.Ping;
import com.inetec.common.net.Telnet;
import com.inetec.common.util.OSInfo;
import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import org.springframework.web.bind.ServletRequestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * 网络管理
 *
 */
public class InterfaceManagerAction extends ActionSupport {
    /**
     * Logger for this class
     */
    private static final Logger logger = Logger.getLogger(InterfaceManagerAction.class);
    private LogService logService;




    /**
     * 判断该网卡是否能够配置网关
     */
    public String checkInterface() throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try{
            String name = ServletRequestUtils.getStringParameter(request,"name");
            logger.info("name: "+name);
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.checkInterfaceName(name);
        } catch (Exception e){
            e.printStackTrace();
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 读取可使用的接口名
     */
    public String readAddInterfaceName() throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json =  "{'success':true,'total':0,'rows':[]}";
        try {
            NetworkUtil networkUtil = new NetworkUtil();
            json = networkUtil.readListInterfaceName();
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "接口管理","用户读取可新增接口名成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "接口管理","用户读取可新增接口名失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }
    /**
     * 连通测试
     *
     */
    public String ping() throws IOException {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String ip = ServletRequestUtils.getStringParameter(request,"ip");
            int count = ServletRequestUtils.getIntParameter(request,"count");
            String pingStr = Ping.exec(ip, count);
            msg = getResult(pingStr);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "连通测试","用户ping成功 ");
        } catch (Exception e) {
            logger.error("连通测试", e);
            logService.newLog("ERROE", SessionUtils.getAccount(request).getUserName(), "连通测试","用户ping失败 ");
            msg = "ping失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response,json,result);
        return null;
    }

    private String getResult(String pingStr) {
        String result = "";
        OSInfo osInfo = OSInfo.getOSInfo();
        if(osInfo.isLinux()){
            String[] pings = pingStr.split("\n");
            for (int i = 0; i < pings.length; i++) {
                if(i<pings.length - 1){
                    result += pings[i].trim()+"<br>";
                }else{
                    result += pings[i].trim();
                }
            }
        }else if(osInfo.isWin()){
            String[] pings = pingStr.split("\r\n");
            for (int i = 0; i < pings.length; i++) {
                if(i<pings.length - 1){
                    result += pings[i].trim()+"<br>";
                }else{
                    result += pings[i].trim();
                }
            }
        }
        if(( result.indexOf("ttl")>-1 && result.indexOf("time")>-1 )
                ||(result.indexOf("bytes")>-1 && result.indexOf("time")>-1
                && result.indexOf("TTL")>-1)){
            result += "<br><font color=\"green\">PING测试成功!</font>";
        } else {
            result += "<br><font color=\"red\">PING测试失败!</font>";
        }
        return result;
    }

    /**
     * 端口测试
     *
     */
    public String telnet() throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String ip = ServletRequestUtils.getStringParameter(request,"ip");
            int port = ServletRequestUtils.getIntParameter(request,"port");
            boolean isTelnet = Telnet.exec(ip, port);
            if(isTelnet){
                logger.info("IP"+ip+"上的端口"+port+"是打开的!");
                msg = "<font color=\"green\">端口是打开的!</font>";
            }else{
                logger.info("IP"+ip+"上的端口"+port+"是关闭的!");
                msg = "<font color=\"red\">端口是关闭的!</font>";
            }
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), "端口测试","用户telnet成功 ");
        } catch (Exception e) {
            logger.error("端口测试", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), "端口测试","用户telnet失败 ");
            msg = "telnet失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response,json,result);
        return null;
    }

    /**
     * 读取路由信息
     *
     */
    public String readRouter() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = "{success:true,total:0,rows:[]}";
        try {
            String startStr = ServletRequestUtils.getStringParameter(request,"start");
            String limitStr = ServletRequestUtils.getStringParameter(request,"limit");
            Integer start = Integer.decode(startStr);
            Integer limit = Integer.decode(limitStr);
            NetworkUtil networkUtil = new NetworkUtil();
            json = networkUtil.readListRouter(start,limit);
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"路由管理","用户读取路由信息成功 ");
        } catch (Exception e) {
            logger.error("路由管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"路由管理","用户读取路由信息失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 读取所有接口名
     *
     */
    public String readInterfaceName() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json =  "{'success':true,'total':0,'rows':[]}";
        String model = "路由管理/接口管理";
        String t = ServletRequestUtils.getStringParameter(request,"t");
        if(t.equals("router")){
            model = "路由管理";
        } else if (t.endsWith("interface")){
            model = "接口管理";
        }
        try {
            NetworkUtil networkUtil = new NetworkUtil();
            json = networkUtil.readListNetInfoName();
//            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(), model,"用户读取所有接口名成功 ");
        } catch (Exception e) {
            logger.error(model, e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(), model,"用户读取所有接口名失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }
    /**
     * 新增一个路由信息
     *
     */
    public String saveRouter() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            String subnetMask = ServletRequestUtils.getStringParameter(request,"subnetMask");
            String gateway = ServletRequestUtils.getStringParameter(request,"gateway");
            String destination  = ServletRequestUtils.getStringParameter(request,"destination");
            NetInfo netInfo = new NetInfo(interfaceName,subnetMask,gateway,destination);
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.saveRouter(netInfo);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"路由管理","用户新增一个路由信息成功 ");

        } catch (Exception e) {
            logger.error("路由管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"路由管理","用户新增一个路由信息失败 ");
            msg = "新增一个路由信息失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 删除一个路由信息
     *
     */
    public String deleteRouter() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String[] destinationArray = ServletRequestUtils.getStringParameters(request,"destinationArray");
            String[] gatewayArray = ServletRequestUtils.getStringParameters(request,"gatewayArray");
            String[] subnetMaskArray = ServletRequestUtils.getStringParameters(request,"subnetMaskArray");
            String[] interfaceNameArray = ServletRequestUtils.getStringParameters(request,"interfaceNameArray");
            NetworkUtil networkUtil = new NetworkUtil();
            List<NetInfo> netInfos = new ArrayList<NetInfo>();
            for (int i = 0; i < destinationArray.length; i++) {
                NetInfo netInfo = new NetInfo();
                netInfo.setDestination(destinationArray[i]);
                netInfo.setInterfaceName(interfaceNameArray[i]);
                netInfo.setSubnetMask(subnetMaskArray[i]);
                netInfo.setGateway(gatewayArray[i]);
                netInfos.add(netInfo);
            }
            msg = networkUtil.deleteRouter(netInfos);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"路由管理","用户删除路由信息成功 ");
        } catch (Exception e) {
            logger.error("路由管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"路由管理","用户删除路由信息失败 ");
            msg = "删除路由信息失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 读取接口信息
     *
     */
    public String readInterface() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = "{success:true,total:0,rows:[]}";
        try {
            String startStr = ServletRequestUtils.getStringParameter(request,"start");
            String limitStr = ServletRequestUtils.getStringParameter(request,"limit");
            Integer start = Integer.decode(startStr);
            Integer limit = Integer.decode(limitStr);
            NetworkUtil networkUtil = new NetworkUtil();
            json = networkUtil.readListNetInfo(start,limit);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户读取接口信息成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户读取接口信息失败 ");
        }
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public String readInterfaceComboBox() throws Exception {
        HttpServletResponse response = (HttpServletResponse) ActionContext.getContext().getContext().get(ServletActionContext.HTTP_RESPONSE);
        response.setCharacterEncoding("UTF-8");
        PrintWriter out = response.getWriter();
        StringBuffer jsonb = new StringBuffer();
        GetListNetInfo getListNetInfo = new GetListNetInfo();
        List<NetInfo> netInfos = getListNetInfo.readInterfaces();
        jsonb.append("{'userlist':").append(netInfos.size()).append(",'rows':[");
        for(NetInfo netInfo : netInfos){
            jsonb.append("{id:'").append(netInfo.getIp());
            jsonb.append("',username:'").append(netInfo.getInterfaceName()+":"+netInfo.getIp()).append("'},");
        }
        jsonb.deleteCharAt(jsonb.length() - 1);
        jsonb.append("]}");
        String jsons = jsonb.toString();
        out.println(jsons);
        out.flush();
        out.close();
        return null;
    }


    /**
     *  激活接口
     *
     */
    public String ifInterfaceUp() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.ifUp(interfaceName);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户激活接口成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户激活接口失败 ");
            msg = "激活接口失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     *  注销接口
     *
     */
    public String ifInterfaceDown() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.ifDown(interfaceName);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户注销接口成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户注销接口失败 ");
            msg = "注销接口失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     * 新增虚拟接口
     *
     */
    public String saveInterface() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            String ip = ServletRequestUtils.getStringParameter(request,"ip");
            Boolean up = ServletRequestUtils.getBooleanParameter(request,"isUp");
            String subnetMask = ServletRequestUtils.getStringParameter(request,"subnetMask");
            String broadCast = ServletRequestUtils.getStringParameter(request,"broadCast");
            NetInfo netInfo = new NetInfo(interfaceName,ip,up, subnetMask,broadCast);
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.saveInterface(netInfo);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户新增虚拟接口信息成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户新增虚拟接口信息失败 ");
            msg = "新增虚拟接口信息失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     *  删除虚拟接口
     *
     */
    public String deleteInterface() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.deleteInterface(interfaceName);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户删除虚拟接口成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户删除虚拟接口失败 ");
            msg = "删除虚拟接口失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }
    /**
     *  修改接口信息
     *
     */
    public String updateInterface() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            String encap = ServletRequestUtils.getStringParameter(request,"encap");
            String ip = ServletRequestUtils.getStringParameter(request,"ip");
            Boolean isUp = ServletRequestUtils.getBooleanParameter(request,"isUp");
            Boolean isUpOlder = ServletRequestUtils.getBooleanParameter(request,"isUpOlder");
            String gateway = ServletRequestUtils.getStringParameter(request,"gateway");
            String gatewayOlder = ServletRequestUtils.getStringParameter(request,"gatewayOlder");
            String subnetMask = ServletRequestUtils.getStringParameter(request,"subnetMask");
            String broadCast = ServletRequestUtils.getStringParameter(request,"broadCast");
            NetInfo netInfo = new NetInfo(interfaceName,encap,ip,isUp,gateway,subnetMask,broadCast);
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.updateInterface(netInfo,isUpOlder,gatewayOlder);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户修改接口信息成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户修改接口信息失败 ");
            msg = "修改接口信息失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }
    /**
     *  修改虚拟接口信息
     *
     */
    public String updateXNInterface() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            String encap = ServletRequestUtils.getStringParameter(request,"encap");
            String ip = ServletRequestUtils.getStringParameter(request,"ip");
            Boolean isUp = ServletRequestUtils.getBooleanParameter(request,"isUp");
            Boolean isUpOlder = ServletRequestUtils.getBooleanParameter(request,"isUpOlder");
            String gateway = ServletRequestUtils.getStringParameter(request,"gateway");
            String gatewayOlder = ServletRequestUtils.getStringParameter(request,"gatewayOlder");
            String subnetMask = ServletRequestUtils.getStringParameter(request,"subnetMask");
            String broadCast = ServletRequestUtils.getStringParameter(request,"broadCast");
            NetInfo netInfo = new NetInfo(interfaceName,encap,ip,isUp,gateway,subnetMask,broadCast);
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.updateInterface(netInfo,isUpOlder,gatewayOlder);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户修改虚拟接口信息成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户修改虚拟接口信息失败 ");
            msg = "修改虚拟接口信息失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    /**
     *  修改DNS信息
     *
     */
    public String updateDNS() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        ActionBase actionBase = new ActionBase();
        String result =	actionBase.actionBegin(request);
        String json = null;
        String msg = null;
        try {
            String interfaceName = ServletRequestUtils.getStringParameter(request,"interfaceName");
            String dns_1 = ServletRequestUtils.getStringParameter(request,"dns_1");
            String dns_2 = ServletRequestUtils.getStringParameter(request,"dns_2");
            NetInfo netInfo = new NetInfo(interfaceName,dns_1,dns_2);
            NetworkUtil networkUtil = new NetworkUtil();
            msg = networkUtil.updateDNS(netInfo);
            logService.newLog("INFO", SessionUtils.getAccount(request).getUserName(),"接口管理","用户修改DNS信息成功 ");
        } catch (Exception e) {
            logger.error("接口管理", e);
            logService.newLog("ERROR", SessionUtils.getAccount(request).getUserName(),"接口管理","用户修改DNS信息失败 ");
            msg = "修改DNS信息失败";
        }
        json = "{success:true,msg:'"+msg+"'}";
        actionBase.actionEnd(response, json, result);
        return null;
    }

    public LogService getLogService() {
        return logService;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }
}
