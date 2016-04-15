<%--
&lt;%&ndash;
  Created by IntelliJ IDEA.
  User: 钱晓盼
  Date: 11-9-21
  Time: 下午1:01
  To change this template use File | Settings | File Templates.
&ndash;%&gt;
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@include file="/taglib.jsp"%>
<%
    String path = request.getContextPath();
    String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
<html>
    <head>
        <title>日志下载</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta http-equiv="pragma" content="no-cache" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <META http-equiv="x-ua-compatible" content="ie=EmulateIE6" />

        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/ext/resources/css/ext-all.css"/>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/ext/resources/css/ext-all-notheme.css"/>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/ext/resources/css/xtheme-blue.css"/>
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/ext-patch.css">
        <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/icon.css"/>
		<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/index.css"/>

        <script type="text/javascript" src="${pageContext.request.contextPath}/js/ext/adapter/ext/ext-base.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/js/ext/ext-all.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/js/ext/ext-lang-zh_CN.js"></script>
        <script type="text/javascript" src="${pageContext.request.contextPath}/js/system/manager-downloadLog.js"></script>

    </head>
    <body>

    </body>
</html>--%>
<%@include file="/include/common.jsp"%>
<head>
    <title>日志下载</title>
    <%--<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/js/redio/RadioboxSelectionModel.css"/>--%>
    <%--<script type="text/javascript" src="${pageContext.request.contextPath}/js/redio/RadioboxSelectionModel.js"></script>--%>
    <script type="text/javascript" src="${pageContext.request.contextPath}/js/system/manager-downloadLog.js"></script>
</head>
