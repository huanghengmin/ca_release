package com.hzih.ca.web.servlet;

import com.hzih.ca.constant.AppConstant;
import com.hzih.ca.constant.ServiceConstant;
import com.hzih.ca.domain.SafePolicy;
import com.hzih.ca.myjfree.RunMonitorInfoList;
import com.hzih.ca.myjfree.RunMonitorLiuliangBean2List;
import com.hzih.ca.service.SafePolicyService;
//import com.hzih.ca.tcp.ServiceUtils;
//import com.hzih.ca.tcp.TcpServer;
//import com.hzih.ca.utils.ServiceUtil;
import com.hzih.ca.web.SiteContext;
import com.inetec.common.util.OSInfo;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.DispatcherServlet;
import javax.servlet.*;
import java.io.IOException;
//import java.net.InetSocketAddress;

public class SiteContextLoaderServlet extends DispatcherServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Log log = LogFactory.getLog(SiteContextLoaderServlet.class);

	@Override
	public void init(ServletConfig config) throws ServletException {
		ServletContext servletContext = config.getServletContext();
        WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(servletContext);
        SiteContext.getInstance().contextRealPath = config.getServletContext().getRealPath("/");
        servletContext.setAttribute("appConstant", new AppConstant());
        SafePolicyService service = (SafePolicyService)context.getBean(ServiceConstant.SAFEPOLICY_SERVICE);
        SafePolicy data = service.getData();
        SiteContext.getInstance().safePolicy = data;

		/*InetSocketAddress localAddressServer = new InetSocketAddress("0.0.0.0", 5001);
		TcpServer tcpServer = new TcpServer();
		tcpServer.init(localAddressServer);
		new Thread(tcpServer).start();*/

		/**
		 * 读取网卡流量
		 */
		OSInfo osinfo = OSInfo.getOSInfo();
		if (osinfo.isLinux()) {
			new RunMonitorInfoList().start();
			new RunMonitorLiuliangBean2List().start();
		}
	}

	@Override
	public ServletConfig getServletConfig() {
		// do nothing
		return null;
	}

	@Override
	public void service(ServletRequest arg0, ServletResponse arg1)
			throws ServletException, IOException {
		// do nothing
	}

	@Override
	public String getServletInfo() {
		// do nothing
		return null;
	}

	@Override
	public void destroy() {

	}

}
