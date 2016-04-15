package com.hzih.ca.web.taglib;

import com.hzih.ca.domain.Account;
import com.hzih.ca.domain.Permission;
import com.hzih.ca.web.SessionUtils;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;
import java.util.Iterator;
import java.util.Set;

/**
 * 
 * @author collin.code@gmail.com
 * 
 */
public class AccessControlTag extends TagSupport {

	private static final long serialVersionUID = 1L;

	/**
	 * 
	 */
	String code;

	public int doStartTag() throws JspException {
		Account account = SessionUtils.getAccount(pageContext);
		Set<Permission> permissions = account.getPermissions();
		for (Iterator<Permission> iter = permissions.iterator(); iter.hasNext();) {
			Permission permission = iter.next();
			if (permission.getCode().equalsIgnoreCase(code)) {
				return EVAL_BODY_INCLUDE;
			}

		}
		return SKIP_BODY;
	}

	public int doEndTag() throws JspException {

		return EVAL_PAGE;
	}

	public void setCode(String code) {
		this.code = code;
	}
}
