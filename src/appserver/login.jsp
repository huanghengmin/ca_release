<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@page contentType="text/html;charset=utf-8" import="com.hzih.ca.web.SiteContext" %>
<%@include file="/taglib.jsp" %>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <title>CA管理中心</title>

    <script language="JavaScript">
        function reloadVerifyCode() {
            document.getElementById('verifyCodeImg').src = "<c:url value="/RandomCodeCtrl"/>" + "?tmp=" + RndNum(9000);
        }

        function checkForm() {
            var form = document.forms.loginForm;
            if (form.name.value == null || form.name.value.length == 0) {
                alert("用户名不能为空！");
                return false;
            }
            var password = form.pwd.value;
            var re = /^[0-9a-zA-Z!$#%@^&*()~_+]{8,20}$/;
            if (!re.test(password)) {
                alert("密码必须为大写字母、小写字母、数字和特殊字符的组合，且不少于8位！");
                return false;
            }
            //re = /([0-9].*([a-zA-Z].*[!$#%@^&*()~_+]|[!$#%@^&*()~_+].*[a-zA-Z])|[a-zA-Z].*([0-9].*[!$#%@^&*()~_+]|[!$#%@^&*()~_+].*[0-9])|[!$#%@^&*()~_+].*([0-9].*[a-zA-Z]|[a-zA-Z].*[0-9]))/;
            //if(!re.test(password)){
            //alert("密码必须为大写字母、小写字母、数字和特殊字符的组合，且不少于8位！");
            //return false;
            //}
            if (form.vcode.value == null || form.vcode.value.length == 0) {
                alert("验证码不能为空！");
                return false;
            }
            return true;
        }

        function down_usbKey(){
            document.getElementById('downUsbKey').href = "<c:url value="/DownLoadUsbKey"/>";
        }

        function down_tfCard(){
            document.getElementById('downTFCard').href = "<c:url value="/DownLoadTFCard"/>";
        }

    </script>
</head>
<body style="background-color:#212936">

<div style="width: 466px; height: 320px; border: 0px solid #000000; margin: 0 auto; margin-top: 120px; background: url(img/ZD-CA.jpg) no-repeat;">

    <form name="loginForm" action="login.action" method="post" style="margin: 0; padding: 0;border:0;"
          onsubmit="return checkForm();">

        <div style="padding: 100px 0 0 180px">

            <table cellspacing=3 cellpadding=0 border=0>
                <tr>
                    <td align=right>用户名：</td>
                    <td><input type="text" name="name" autocomplete="off" style="width:140px;"/></td>
                </tr>
                <tr>
                    <td align=right>密&nbsp;&nbsp;码：</td>
                    <td><input type="password" name="pwd" autocomplete="off" style="width:140px;"/></td>
                </tr>
                <tr>
                    <td align=right>验证码：</td>
                    <td><INPUT TYPE="text" autocomplete="off" NAME="vcode" style="width: 80px;"><img
                            src="<c:url value="/RandomCodeCtrl"/>" height="20" width="60"
                            align="absmiddle" id="verifyCodeImg" onclick="reloadVerifyCode();"
                            alt="单击更换验证码" style="cursor: hand;"/></td>
                </tr>
                <tr>
                    <td/>
                    <td><input type="submit" value="登&nbsp;&nbsp;录"/>&nbsp;&nbsp;
                        <input type="reset" value="取&nbsp;&nbsp;消"/></td>
                </tr>
                <tr>
                    <td/>
                    <td>
                        <a href="javascript:void(0);" id="downUsbKey" onclick="down_usbKey();"><font color="#00008b">UsbKey驱动</font></a> &nbsp;&nbsp;
                        <a href="javascript:void(0);" id="downTFCard" onclick="down_tfCard();"><font color="#00008b">TFCard驱动</font></a>
                </tr>
            </table>
        </div>
    </form>
</div>
</body>
</html>

