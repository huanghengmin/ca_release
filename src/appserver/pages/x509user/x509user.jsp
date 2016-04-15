<%--
<%@page contentType="text/html;charset=utf-8"%>
<%@include file="/taglib.jsp"%>
<%@ taglib uri="/struts-tags" prefix="s" %>
<%
String path = request.getContextPath();
String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>

<html version="-//W3C//DTD HTML 4.01 Transitional//EN">
    <head>
        <title>用户证书管理</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta http-equiv="pragma" content="no-cache" />
		<meta http-equiv="cache-control" content="no-cache" />
		<meta http-equiv="expires" content="0" />
		<META http-equiv="x-ua-compatible" content="ie=EmulateIE7" />
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/ext/resources/css/ext-all.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/ext/resources/css/ext-all-notheme.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/ext/resources/css/xtheme-blue.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/ext-patch.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/icon.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/index.css"/>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/ext/adapter/ext/ext-base.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/ext/ext-all.js"></script>
		<script type="text/javascript" src="${pageContext.request.contextPath}/js/ext/ext-lang-zh_CN.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/js/x509user/x509user.js"></script>
    </head>
<body>
<OBJECT ID="ZdActivex" HEIGHT=0 WIDTH=0  ALIGN="CENTER"
        CLASSID="CLSID:5F0ECE95-9BBB-4F87-B2C6-2D7EB0F0F454"
        CODEBASE="<%=basePath%>ZdActivex.cab#version=1,0,0,1">
</OBJECT>
</body>
</html>
--%>
<html>
<%@include file="/include/common.jsp"%>
<%
    String path = request.getContextPath();
    String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
<head>
    <title>设备证书管理</title>
    <script type="text/javascript" src="${pageContext.request.contextPath}/js/x509user/x509user.js"></script>
</head>
<body>
<OBJECT ID="ZdActivex" HEIGHT=0 WIDTH=0  ALIGN="CENTER"
        CLASSID="CLSID:5F0ECE95-9BBB-4F87-B2C6-2D7EB0F0F454"
        CODEBASE="<%=basePath%>ZdActivex.cab#version=1,0,0,1">
</OBJECT>
</body>
</html>
