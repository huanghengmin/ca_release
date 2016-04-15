package com.hzih.ca.web.action.user;

import cn.collin.commons.utils.DateUtils;
import com.hzih.ca.domain.Account;
import com.hzih.ca.service.LogService;
import com.hzih.ca.service.LoginService;
import com.hzih.ca.utils.Constant;
import com.hzih.ca.web.SessionUtils;
import com.hzih.ca.web.SiteContext;
import com.inetec.common.net.NicMac;
import com.inetec.common.security.DesEncrypterAsPassword;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

/**
 * 用户登录
 * 
 * @author collin.code@gmail.com
 * @struts.action type="org.springframework.web.struts.DelegatingActionProxy"
 *                scope="request" path="/login" validate="false"
 * @struts.action-forward name="login" path="/loginError.jsp"
 * @struts.action-forward name="index" path="/" redirect="true"
 */
public class LoginAction extends ActionSupport {
	/**
	 * Logger for this class
	 */
	private static final Logger logger = Logger.getLogger(LoginAction.class);
	private LoginService loginService;
	private LogService logService;
//    private SecurityService securityService;

	public String execute() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
		String name = request.getParameter("name");
		String pwd = request.getParameter("pwd");
		String vcode = request.getParameter("vcode");

		if (SessionUtils.getAccount(request) != null) {
			SessionUtils.removeAccount(request);
		}

		final String ip = request.getRemoteAddr();
		Object obj = SiteContext.getInstance().loginErrorList.get(ip);
		int errorLimit = SiteContext.getInstance().safePolicy.getErrorLimit();
		int lockTime = SiteContext.getInstance().safePolicy.getLockTime();
		if (obj != null && ((Integer) obj).intValue() >= errorLimit) {
			logger.info("超过" + errorLimit + "次口令错误，请联系系统管理员！ ");
//			securityService.addSecurityAlert("登陆单项光闸服务器",new Date(),"0010","在"+ getIpAddr(request)+ "登陆超过3次口令错误","N",getIpAddr(request));
            logService.newLog("WARN", "登陆", "黑客入侵", "在" + getIpAddr(request) + "登陆超过3次口令错误");
			request.setAttribute("message", "超过" + errorLimit	+ "次口令错误,系统锁定,请联系系统管理员!");
			new Timer().schedule(new TimerTask(){
				public void run() {
				SiteContext.getInstance().loginErrorList.remove(ip);
				}
			}, lockTime*60*60*1000);     //ip 停用 lockTime 小时
			return "failure";
		}

		if (null == name || null == pwd/* || null == vcode*/) {
            logger.info(" 用户名、密码或验证码为空！ ");
            request.setAttribute("message", " 用户名、密码或验证码为空！ ");
            return "failure";
        }

		if (!vcode.equalsIgnoreCase(SessionUtils.getVcode(request))) {
			logger.info(" 验证码出错！ ");
			request.setAttribute("message", " 验证码出错！ ");
			return "failure";
		}
        DesEncrypterAsPassword deap = new DesEncrypterAsPassword(Constant.S_PWD_ENCRYPT_CODE);
        String password = new String(deap.encrypt(pwd.getBytes()));
		Account account = loginService.getAccountByNameAndPwd(name, password);
		if (account != null) {
			logger.info(" 用户名和密码验证通过！ ");
			logger.debug(SiteContext.getInstance().safePolicy.getRemoteDisabled()
					+ "|" + account.getRemoteIp() + "|" + ip);
            if(SiteContext.getInstance().safePolicy.getMacDisabled()){
                NicMac nicMac = new NicMac(ip);
                if(account.getMac()!=null){
                    String mac = nicMac.GetRemoteMacAddr();
                    if(!mac.equals(account.getMac())){
                        request.setAttribute("message", "MAC地址错误!");
                        return "failure";
                    }
                } else {
                    request.setAttribute("message", "MAC地址错误!");
                    return "failure";
                }
            }
            /**
             *  isTime == true 工作时间(允许访问的时间)
             *  isIp == true 允许访问的ip
             */
            boolean isTime = checkTime(account);
            boolean isIp = checkIp(account,request);
            if(isTime){
                if(isIp){
                    logger.info(" 用户名和密码验证通过!");
                    SessionUtils.setAccount(request, account);
                    SessionUtils.setLoginTime(request, DateUtils.getNow().getTime());
                    logService.newLog("INFO", account.getUserName(), "用户登录", "用户登录成功");
                    // 登录错误数置零
                    Object _obj = SiteContext.getInstance().loginErrorList.get(ip);
                    if (_obj != null) {
                        SiteContext.getInstance().loginErrorList.put(ip, new Integer(0));
                    }
                    return "success";
                } else {
                    logger.info("非法登陆IP!");
                    request.setAttribute("message", "非法登陆IP!");
                    logService.newLog("INFO", name, " 用户登录 ", " IP地址不允许访问 ");
                }
            } else {
                logger.info("非法登陆时间!");
                request.setAttribute("message", "非法登陆时间!");
                logService.newLog("INFO", name, " 用户登录 ", " 该时间不允许访问 ");
            }
		} else {
            Account _account = loginService.getAccountByName(name);
            if(_account!=null){
                logger.info(" 密码错误！ ");
                logService.newLog("INFO", name, " 用户登录 ", " 密码错误 ");
            } else {
                logger.info(" 用户名不存在！ ");
                logService.newLog("INFO", name, " 用户登录 ", " 用户名不存在 ");
            }
            request.setAttribute("message", " 用户名、密码错误！ ");
            Object _obj = SiteContext.getInstance().loginErrorList.get(ip);
			if (_obj == null) {
				SiteContext.getInstance().loginErrorList.put(ip, new Integer(1));
			} else {
				SiteContext.getInstance().loginErrorList.put(ip, new Integer(((Integer) _obj).intValue() + 1));
			}
		}
        return "failure";
	}

	public String getIpAddr(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");
        if(ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if(ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if(ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private boolean checkTime(Account account) {
		int startHour = account.getStartHour();
		int endHour = account.getEndHour();
		int hour = Calendar.HOUR+1;
		if(hour >= startHour && hour <= endHour){
			return true;
		}
		return false;
	}

	private boolean checkIp(Account account,HttpServletRequest request) {
		String ip = this.getIpAddr(request);
        if(account.getIpType()==1){
            String startIp = account.getStartIp();
            String endIp = account.getEndIp();
            try {
                long ipLong = getIP(InetAddress.getByName(ip));
                long startIpLong = getIP(InetAddress.getByName(startIp));
                long endIpLong = getIP(InetAddress.getByName(endIp));
                if(ipLong >= startIpLong && ipLong <= endIpLong){
                    return true;
                }
            } catch (UnknownHostException e) {
                logger.error("用户登陆",e);
            }
        } else {
            String remoteIp = account.getRemoteIp();
            try {
                long ipLong = getIP(InetAddress.getByName(ip));
                long remoteIpLong = getIP(InetAddress.getByName(remoteIp));
                if(ipLong==remoteIpLong) {
                    return true;
                }
            } catch (UnknownHostException e) {
                logger.error("用户登陆",e);
            }
        }
		return false;
	}

    /**
	 * ip转成long类型
	 * @param ip
	 * @return
	 */
	public long getIP(InetAddress ip) {
        byte[] b = ip.getAddress();
        long l = b[0] << 24L & 0xff000000L | b[1] << 16L & 0xff0000L
                | b[2] << 8L & 0xff00 | b[3] << 0L & 0xff;
        return l;
    }

    public void setLogService(LogService logService) {
        this.logService = logService;
    }

    public void setLoginService(LoginService loginService) {
        this.loginService = loginService;
    }

    public LoginService getLoginService() {
        return loginService;
    }

    public LogService getLogService() {
        return logService;
    }
}
