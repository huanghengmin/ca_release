<%@page contentType="text/html;charset=utf-8"%>
<%@include file="/include/common.jsp"%>
<%@include file="/taglib.jsp"%>

<c:if test="${account==null}">
	<%response.sendRedirect("login.jsp");%>
</c:if>
<html>
    <head>
        <title>管理中心</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta http-equiv="pragma" content="no-cache" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <META http-equiv="x-ua-compatible" content="ie=EmulateIE6" />

<%--<script type="text/javascript" language="Javascript" src="<c:url value="/js/extux.js"/>"></script>--%>
<%--<script type="text/javascript" language="Javascript" src="<c:url value="/js/index.jsp"/>"></script>--%>
    </head>
    <body>
        <DIV>
            <script type="text/javascript">
                var centerPanel;
                var idx;
                var idx2;
                Ext.onReady(function() {
                    Ext.BLANK_IMAGE_URL = 'js/ext/resources/images/default/tree/s.gif';
                    Ext.QuickTips.init();
                    Ext.form.Field.prototype.msgTarget = 'side';

                    var menu_root_node_1 = new Ext.tree.TreeNode({
                        text : '权限管理',
                        expanded : false
                    });
                    var menu_root_node_2 = new Ext.tree.TreeNode({
                        text : '网络管理',
                        expanded : false
                    });
                    var menu_root_node_3 = new Ext.tree.TreeNode({
                        text : '系统管理',
                        expanded : false
                    });
                    var menu_root_node_4 = new Ext.tree.TreeNode({
                        text : '配置管理',
                        expanded : false
                    });
                    var menu_root_node_5 = new Ext.tree.TreeNode({
                        text : '审计管理',
                        expanded : false
                    });
                    var menu_root_node_6 = new Ext.tree.TreeNode({
                        text : '报警管理',
                        expanded : false
                    });
                    var menu_root_node_7 = new Ext.tree.TreeNode({
                        text : '运行监控',
                        expanded : false
                    });
                    var menu_root_node_8 = new Ext.tree.TreeNode({
                        text : '数据源管理',
                        expanded : false
                    });
                    var menu_root_node_9 = new Ext.tree.TreeNode({
                        text : '应用管理',
                        expanded : false
                    });
                    var menu_root_node_10 = new Ext.tree.TreeNode({
                        text : '审核管理',
                        expanded : false
                    });

                    var mrn_1_1 = new Ext.tree.TreeNode({
                        id: 'mrn_1_1',
                        text: '用户管理',
                        leaf: true ,
                        url: 'pages/user/userIndex.jsp'
                    }) ;
                    var mrn_1_2 = new Ext.tree.TreeNode({
                        id: 'mrn_1_2',
                        text: '角色管理',
                        leaf: true ,
                        url: 'pages/user/roleIndex.jsp'
                    }) ;
                    var mrn_1_3 = new Ext.tree.TreeNode({
                        id: 'mrn_1_3',
                        text: '安全策略',
                        leaf: true ,
                        url: 'pages/user/safePolicy.jsp'
                    }) ;
                    <lbs:access code="SECOND_YHGL">
                    menu_root_node_1.appendChild(mrn_1_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_JSGL">
                    menu_root_node_1.appendChild(mrn_1_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_AQCL">
                    menu_root_node_1.appendChild(mrn_1_3) ;
                    </lbs:access>

                    var mrn_2_1 = new Ext.tree.TreeNode({
                        id: 'mrn_2_1',
                        text: '接口管理',
                        leaf: true ,
                        url: 'pages/net/manager_interface.jsp'
                    }) ;
                    var mrn_2_2 = new Ext.tree.TreeNode({
                        id: 'mrn_2_2',
                        text: '路由管理',
                        leaf: true ,
                        url: 'pages/net/manager_router.jsp'
                    }) ;
                    var mrn_2_3 = new Ext.tree.TreeNode({
                        id: 'mrn_2_3',
                        text: '网络测试',
                        leaf: true ,
                        url: 'pages/net/manager_pingTelnet.jsp'
                    }) ;
                    var mrn_2_4 = new Ext.tree.TreeNode({
                        id: 'mrn_2_4',
                        text: '安全配置',
                        leaf: true ,
                        url: 'pages/net/manager_security_config.jsp'
                    }) ;

                    <lbs:access code="SECOND_JKGL">
                    menu_root_node_2.appendChild(mrn_2_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_LYGL">
                    menu_root_node_2.appendChild(mrn_2_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_WLCS">
                    menu_root_node_2.appendChild(mrn_2_3) ;
                    </lbs:access>
                    <lbs:access code="SECOND_AQPZ">
                    menu_root_node_2.appendChild(mrn_2_4) ;
                    </lbs:access>


                    var mrn_3_1 = new Ext.tree.TreeNode({
                        id: 'mrn_3_1',
                        text: '平台说明',
                        leaf: true ,
                        url: 'pages/system/manager_version.jsp'
                    }) ;
                    var mrn_3_2 = new Ext.tree.TreeNode({
                        id: 'mrn_3_2',
                        text: '平台管理',
                        leaf: true ,
                        url: 'pages/system/manager_platform.jsp'
                    }) ;
                    var mrn_3_3 = new Ext.tree.TreeNode({
                        id: 'mrn_3_3',
                        text: '平台初始化',
                        leaf: true ,
                        url: 'pages/system/manager_init_source.jsp'
                    }) ;
                    var mrn_3_4 = new Ext.tree.TreeNode({
                        id: 'mrn_3_4',
                        text: '许可证管理',
                        leaf: true ,
                        url: 'pages/system/manager_license.jsp'
                    }) ;
                    var mrn_3_5 = new Ext.tree.TreeNode({
                        id: 'mrn_3_5',
                        text: '日志下载',
                        leaf: true ,
                        url: 'pages/system/manager_downloadLog.jsp'
                    }) ;
                    var mrn_3_6 = new Ext.tree.TreeNode({
                        id: 'mrn_3_6',
                        text: '版本升级',
                        leaf: true ,
                        url: 'pages/system/manager_upgrade_version.jsp'
                    }) ;
                    var mrn_3_7 = new Ext.tree.TreeNode({
                        id: 'mrn_3_7',
                        text: '源端配置恢复',
                        leaf: true ,
                        url: 'pages/system/manager_recover_config_source.jsp'
                    }) ;
                    var mrn_3_8 = new Ext.tree.TreeNode({
                        id: 'mrn_3_8',
                        text: '目标配置恢复',
                        leaf: true ,
                        url: 'pages/system/manager_recover_config_target.jsp'
                    }) ;
                    var mrn_3_9 = new Ext.tree.TreeNode({
                        id: 'mrn_3_9',
                        text: '源端配置文件管理',
                        leaf: true ,
                        url: 'pages/system/manager_config_file_source.jsp'
                    }) ;
                    var mrn_3_10 = new Ext.tree.TreeNode({
                        id: 'mrn_3_10',
                        text: '目标配置文件管理',
                        leaf: true ,
                        url: 'pages/system/manager_config_file_target.jsp'
                    }) ;
                    var mrn_3_11 = new Ext.tree.TreeNode({
                        id: 'mrn_3_11',
                        text: '平台配置',
                        leaf: true ,
                        url: 'pages/system/manager_platform_config.jsp'
                    }) ;
                    var mrn_3_12 = new Ext.tree.TreeNode({
                        id: 'mrn_3_12',
                        text: '恢复出厂设置',
                        leaf: true ,
                        url: 'pages/system/manager_platform_reset.jsp'
                    }) ;
                    var mrn_3_13 = new Ext.tree.TreeNode({
                        id: 'mrn_3_13',
                        text: '平台初始化',
                        leaf: true ,
                        url: 'pages/system/manager_init_target.jsp'
                    }) ;
                    <lbs:access code="SECOND_INIT_S">
                    menu_root_node_3.appendChild(mrn_3_3) ;
                    </lbs:access>
                    <lbs:access code="SECOND_INIT_T">
                    menu_root_node_3.appendChild(mrn_3_13) ;
                    </lbs:access>
                    <lbs:access code="SECOND_PTPZ">
                    menu_root_node_3.appendChild(mrn_3_11) ;
                    </lbs:access>
                    <lbs:access code="SECOND_PTSM">
                    menu_root_node_3.appendChild(mrn_3_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_PTGL">
                    menu_root_node_3.appendChild(mrn_3_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_ZSGL">
                    menu_root_node_3.appendChild(mrn_3_4) ;
                    </lbs:access>
                    <lbs:access code="SECOND_RZXZ">
                    menu_root_node_3.appendChild(mrn_3_5) ;
                    </lbs:access>
                    <lbs:access code="SECOND_BBSJ">
                    menu_root_node_3.appendChild(mrn_3_6) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_PZHF">
                    menu_root_node_3.appendChild(mrn_3_7) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_PZHF">
                    menu_root_node_3.appendChild(mrn_3_8) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_PZWJGL">
                    menu_root_node_3.appendChild(mrn_3_9) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_PZWJGL">
                    menu_root_node_3.appendChild(mrn_3_10) ;
                    </lbs:access>
                    <lbs:access code="SECOND_HFCCSZ">
                    menu_root_node_3.appendChild(mrn_3_12) ;
                    </lbs:access>

                    var mrn_4_1 = new Ext.tree.TreeNode({
                        id: 'mrn_4_1',
                        text: '审计库配置',
                        leaf: true ,
                        url: 'pages/config/manager_database.jsp'
                    }) ;
                    var mrn_4_2 = new Ext.tree.TreeNode({
                        id: 'mrn_4_2',
                        text: '报警配置',
                        leaf: true ,
                        url: 'pages/config/alert_config.jsp'
                    }) ;
                    var mrn_4_3 = new Ext.tree.TreeNode({
                        id: 'mrn_4_3',
                        text: '设备配置',
                        leaf: true ,
                        url: 'pages/config/manager_equipment.jsp'
                    }) ;
                    var mrn_4_4 = new Ext.tree.TreeNode({
                        id: 'mrn_4_4',
                        text: '双机热备',
                        leaf: true ,
                        url: 'pages/config/manager_equipment_backup.jsp'
                    }) ;
                    var mrn_4_5 = new Ext.tree.TreeNode({
                        id: 'mrn_4_5',
                        text: '信息安全策略',
                        leaf: true ,
                        url: 'pages/config/manager_security_level.jsp'
                    }) ;
                    var mrn_4_6 = new Ext.tree.TreeNode({
                        id: 'mrn_4_6',
                        text: '过滤配置',
                        leaf: true ,
                        url: 'pages/config/manager_content_filter.jsp'
                    }) ;
                    <lbs:access code="SECOND_SJKPZ">
                    menu_root_node_4.appendChild(mrn_4_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_BJPZ">
                    menu_root_node_4.appendChild(mrn_4_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_SBPZ">
                    menu_root_node_4.appendChild(mrn_4_3) ;
                    </lbs:access>
                    <lbs:access code="SECOND_SJRB">
                    menu_root_node_4.appendChild(mrn_4_4) ;
                    </lbs:access>
                    <lbs:access code="SECOND_XXAQCL">
                    menu_root_node_4.appendChild(mrn_4_5) ;
                    </lbs:access>
                    <lbs:access code="SECOND_GLPZ">
                    menu_root_node_4.appendChild(mrn_4_6) ;
                    </lbs:access>

                    var mrn_5_1 = new Ext.tree.TreeNode({
                        id: 'mrn_5_1',
                        text: '管理员日志',
                        leaf: true ,
                        url: 'pages/audit/audit_user.jsp'
                    }) ;
                    var mrn_5_2 = new Ext.tree.TreeNode({
                        id: 'mrn_5_2',
                        text: '设备日志',
                        leaf: true ,
                        url: 'pages/audit/audit_equipment.jsp'
                    }) ;
                    var mrn_5_3 = new Ext.tree.TreeNode({
                        id: 'mrn_5_3',
                        text: '业务日志',
                        leaf: true ,
                        url: 'pages/audit/audit_business.jsp'
                    }) ;

                    var mrn_5_6 = new Ext.tree.TreeNode({
                        id: 'mrn_5_6',
                        text: '系统日志',
                        leaf: true ,
                        url: 'pages/audit/audit_os.jsp'
                    }) ;
                    <lbs:access code="SECOND_YHRZ">
                    menu_root_node_5.appendChild(mrn_5_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_XTRZ">
                    menu_root_node_5.appendChild(mrn_5_6) ;
                    </lbs:access>
                    <lbs:access code="SECOND_SBRZ">
                    menu_root_node_5.appendChild(mrn_5_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YWRZ">
                    menu_root_node_5.appendChild(mrn_5_3) ;
                    </lbs:access>


                    var mrn_6_1 = new Ext.tree.TreeNode({
                        id: 'mrn_6_1',
                        text: '设备故障报警',
                        leaf: true ,
                        url: 'pages/security/alert_equipment_error.jsp'
                    }) ;
                    var mrn_6_2 = new Ext.tree.TreeNode({
                        id: 'mrn_6_2',
                        text: '业务异常报警',
                        leaf: true ,
                        url: 'pages/security/alert_business_exception.jsp'
                    }) ;
                    var mrn_6_3 = new Ext.tree.TreeNode({
                        id: 'mrn_6_3',
                        text: '安全事件报警',
                        leaf: true ,
                        url: 'pages/security/alert_safe_event.jsp'
                    }) ;
                    <lbs:access code="SECOND_SBGZBJ">
                    menu_root_node_6.appendChild(mrn_6_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YWYCBJ">
                    menu_root_node_6.appendChild(mrn_6_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_AQSJBJ">
                    menu_root_node_6.appendChild(mrn_6_3) ;
                    </lbs:access>

                    var mrn_7_1 = new Ext.tree.TreeNode({
                        id: 'mrn_7_1',
                        text: '业务运行监控',
                        leaf: true ,
                        url: 'pages/monitor/monitor_business.jsp'
                    }) ;
                    var mrn_7_2 = new Ext.tree.TreeNode({
                        id: 'mrn_7_2',
                        text: '设备运行监控',
                        leaf: true ,
                        url: 'pages/monitor/monitor_equipment.jsp'
                    }) ;
                    <lbs:access code="SECOND_YWYXJK">
                    menu_root_node_7.appendChild(mrn_7_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_SBYXJK">
                    menu_root_node_7.appendChild(mrn_7_2) ;
                    </lbs:access>

                    var mrn_8_1 = new Ext.tree.TreeNode({
                        id: 'mrn_8_1',
                        text: '源端数据源',
                        leaf: true ,
                        url: 'pages/jdbc/jdbc_external.jsp'
                    }) ;
                    var mrn_8_2 = new Ext.tree.TreeNode({
                        id: 'mrn_8_2',
                        text: '目标数据源',
                        leaf: true ,
                        url: 'pages/jdbc/jdbc_internal.jsp'
                    }) ;
                    <lbs:access code="SECOND_YDSJY">
                    menu_root_node_8.appendChild(mrn_8_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MBSJY">
                    menu_root_node_8.appendChild(mrn_8_2) ;
                    </lbs:access>

                    var mrn_9_1 = new Ext.tree.TreeNode({
                        id: 'mrn_9_1',
                        text: '未通过审核的应用',
                        leaf: true ,
                        url: 'pages/app/manager_type_check.jsp'
                    }) ;
                    var mrn_9_2 = new Ext.tree.TreeNode({
                        id: 'mrn_9_2',
                        text: '目标文件同步',
                        leaf: true ,
                        url: 'pages/app/manager_target_file.jsp'
                    }) ;
                    var mrn_9_3 = new Ext.tree.TreeNode({
                        id: 'mrn_9_3',
                        text: '目标数据库同步',
                        leaf: true ,
                        url: 'pages/app/manager_target_db.jsp'
                    }) ;
                    var mrn_9_4 = new Ext.tree.TreeNode({
                        id: 'mrn_9_4',
                        text: '目标通用代理',
                        leaf: true ,
                        url: 'pages/app/manager_target_proxy.jsp'
                    }) ;
                    var mrn_9_5 = new Ext.tree.TreeNode({
                        id: 'mrn_9_5',
                        text: '端口映射',
                        leaf: true ,
                        url: 'pages/app/manager_proxy_query.jsp'
                    }) ;
                    var mrn_9_6 = new Ext.tree.TreeNode({
                        id: 'mrn_9_6',
                        text: '源端文件同步',
                        leaf: true ,
                        url: 'pages/app/manager_source_file.jsp'
                    }) ;
                    var mrn_9_7 = new Ext.tree.TreeNode({
                        id: 'mrn_9_7',
                        text: '源端数据库同步',
                        leaf: true ,
                        url: 'pages/app/manager_source_db.jsp'
                    }) ;
                    var mrn_9_8 = new Ext.tree.TreeNode({
                        id: 'mrn_9_8',
                        text: '源端通用代理',
                        leaf: true ,
                        url: 'pages/app/manager_source_proxy.jsp'
                    }) ;
                    var mrn_9_9 = new Ext.tree.TreeNode({
                        id: 'mrn_9_9',
                        text: '业务审计比对',
                        leaf: true ,
                        url: 'pages/audit/audit_business_compare.jsp'
                    }) ;
                    var mrn_9_10 = new Ext.tree.TreeNode({
                        id: 'mrn_9_10',
                        text: '业务手动重传',
                        leaf: true ,
                        url: 'pages/audit/audit_business_manual_reset.jsp'
                    }) ;


                    <lbs:access code="SECOND_MB_WJTB">
                    menu_root_node_9.appendChild(mrn_9_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_DBTB">
                    menu_root_node_9.appendChild(mrn_9_3) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_TYDL">
                    menu_root_node_9.appendChild(mrn_9_4) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_WJTB">
                    menu_root_node_9.appendChild(mrn_9_6) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_DBTB">
                    menu_root_node_9.appendChild(mrn_9_7) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_TYDL">
                    menu_root_node_9.appendChild(mrn_9_8) ;
                    </lbs:access>
                    <lbs:access code="SECOND_DKYS">
                    menu_root_node_9.appendChild(mrn_9_5) ;
                    </lbs:access>
                    <lbs:access code="SECOND_PZGL">
                    menu_root_node_9.appendChild(mrn_9_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YWSJBD">
                    menu_root_node_9.appendChild(mrn_9_9) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YWSDCC">
                    menu_root_node_9.appendChild(mrn_9_10) ;
                    </lbs:access>

                    var mrn_10_1 = new Ext.tree.TreeNode({
                        id: 'mrn_10_1',
                        text: '源端文件同步审核',
                        leaf: true ,
                        url: 'pages/appauth/manager_source_allow_file.jsp'
                    }) ;
                    var mrn_10_2 = new Ext.tree.TreeNode({
                        id: 'mrn_10_2',
                        text: '目标文件同步审核',
                        leaf: true ,
                        url: 'pages/appauth/manager_target_allow_file.jsp'
                    }) ;
                    var mrn_10_3 = new Ext.tree.TreeNode({
                        id: 'mrn_10_3',
                        text: '源端数据库同步审核',
                        leaf: true ,
                        url: 'pages/appauth/manager_source_allow_db.jsp'
                    }) ;
                    var mrn_10_4 = new Ext.tree.TreeNode({
                        id: 'mrn_10_4',
                        text: '目标数据库同步审核',
                        leaf: true ,
                        url: 'pages/appauth/manager_target_allow_db.jsp'
                    }) ;
                    var mrn_10_5 = new Ext.tree.TreeNode({
                        id: 'mrn_10_5',
                        text: '源端通用代理审核',
                        leaf: true ,
                        url: 'pages/appauth/manager_source_allow_proxy.jsp'
                    }) ;
                    var mrn_10_6 = new Ext.tree.TreeNode({
                        id: 'mrn_10_6',
                        text: '目标通用代理审核',
                        leaf: true ,
                        url: 'pages/appauth/manager_target_allow_proxy.jsp'
                    }) ;
                    <lbs:access code="SECOND_YD_WJTBSH">
                    menu_root_node_10.appendChild(mrn_10_1) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_WJTBSH">
                    menu_root_node_10.appendChild(mrn_10_2) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_DBTBSH">
                    menu_root_node_10.appendChild(mrn_10_3) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_DBTBSH">
                    menu_root_node_10.appendChild(mrn_10_4) ;
                    </lbs:access>
                    <lbs:access code="SECOND_YD_TYDLSH">
                    menu_root_node_10.appendChild(mrn_10_5) ;
                    </lbs:access>
                    <lbs:access code="SECOND_MB_TYDLSH">
                    menu_root_node_10.appendChild(mrn_10_6) ;
                    </lbs:access>

                    var tree_menu_1 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_1,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_2 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_2,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_3 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_3,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_4 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_4,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_5 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_5,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_6 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_6,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_7 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_7,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_8 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_8,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_9 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_9,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });
                    var tree_menu_10 = new Ext.tree.TreePanel({
                        border: false,
                        root: menu_root_node_10,
                        rootVisible: false,
                        listeners: {
                            click: nodeClick
                        }
                    });

                    function nodeClick(node, e){
                        if (node.isLeaf()){
                            var _url = node.attributes.url ;
                            if (_url != ''){
                                if(_url.indexOf('?')>0)
                                    _url += '&time=' + new Date().getTime();
                                else
                                    _url += '?time=' + new Date().getTime();
                            }
                            var _tab = centerPanel.getComponent(node.id) ;
                            if(!_tab){
                                centerPanel.add({
                                    id: node.id ,
                                    title: node.text ,
                                    closable: true ,
                                    iconCls: node.attributes.iconCls,
                                    html: '<iframe id="frame_'+node.id+'" width="100%" height="100%" frameborder="0" src="'+_url+'"></iframe>',
                                    listeners:{
                                        show:function(){
                                            var mID = centerPanel.getActiveTab().getId();
                                            if(centerPanel.getActiveTab().getStateId()==null){
                                                window.frames[0].location.reload();
                                            }else{
                                                if(window.parent.document.getElementById('frame_'+mID)!=null){
                                                    window.parent.document.getElementById('frame_'+mID).contentWindow.location.reload();
                                                }
                                            }
                                        }
                                    }
                                }) ;
                            }
                            centerPanel.setActiveTab(node.id) ;
                        }
                    }

                    var northBar = new Ext.Toolbar({
                        id: 'northBar',
                        items: [{
                                xtype: 'tbtext',
                                id: 'msg_title',
                                text: ''
                            },{
                                xtype: "tbfill"
                            },{
                                id:'warningMsg',
                                iconCls: 'warning',
                                hidden:true,
                                handler:function(){
                                    eastPanel.expand(true);
                                }
                            },
                                '<a id="sethome.info" onclick="SetHome(this,window.location)"></a>'
                            ,{
                                xtype: 'tbseparator'
                            },{
                                pressed:false,
                                text:'刷新',
                                iconCls: 'refresh',
                                handler: function(){
                                    var mID = centerPanel.getActiveTab().getId();
                                    if(centerPanel.getActiveTab().getStateId()==null){
                                        window.frames[0].location.reload();
                                    }else{
                                        window.parent.document.getElementById('frame_'+mID).contentWindow.location.reload();
                                    }
                                }
                            },{
                                xtype: 'tbseparator'
                            },{
                                text:'加入收藏',
                                iconCls: 'favorite',
                                handler: function(){
                                    AddFavorite(location.href,document.title);
                                }
                            },{
                                 xtype: 'tbseparator'
                            },{
                                 pressed:false,
                                 text:'帮助',
                                 iconCls: 'help',
                                 handler: function(){
                                     window.open('help.doc');
                                 }
                            },{
                                xtype: 'tbseparator'
                            },{
                                id:'logout.tb.info',
                                text:'退出系统',
                                iconCls: 'logout',
                                handler: function(){
                                    logout();
                                }
                            }
                        ]
                    });

                    //页面的上部分
                    var northPanel=new Ext.Panel({
                        region : 'north',			//北部，即顶部，上面
//                        contentEl : 'top-div',		//面板包含的内容
                        split : false,
                        titlebar: false,
                        border: false, 				//是否显示边框
                        collapsible: false, 		//是否可以收缩,默认不可以收缩，即不显示收缩箭头
                        height : 100,
                        html:'<div id="top" style="border:1px solid #564b47;background-color:#fff;height:55;width:100%;background-image: url(img/top.png);">' +
                                    '<div style="height:55;border:0 solid #564b47;float:right;width:400px;margin:0px 0px 0px 0px;background-image: url(img/top_1.png);">' +
                                    '</div>' +
                                '</div>',
                        bbar: northBar
                    });

                    //左边菜单
                    var  westPanel=new Ext.Panel({
                        title : '系统功能',			//面板名称
                        region : 'west',			//该面板的位置，此处是西部 也就是左边
                        split : true,				//为true时，布局边框变粗 ,默认为false
                        titlebar: true,
                        collapsible: true,
                        animate: true,
                        border : true,
                        bodyStyle: 'border-bottom: 0px solid;',
                        bodyborder: true,
                        width : 200,
                        minSize : 100,				//最小宽度
                        maxSize : 300,
                        layout : 'accordion',
                        iconCls : 'title-1',
                        layoutConfig : { 			//布局
                            titleCollapse : true,
                            animate : true
                        },
                        items : [

                            <lbs:access code="TOP_QXGL" >
                            {
                                title: '权限管理',
                                border: false,
                                iconCls:'user',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_1]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_WLGL" >
                            {
                                title: '网络管理',
                                border: false,
                                iconCls:'wlgl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_2]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_XTGL" >
                            {
                                title: '系统管理',
                                border: false,
                                iconCls:'xtgl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_3]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_PZGL" >
                            {
                                title: '配置管理',
                                border: false,
                                iconCls:'pzgl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_4]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_SJGL" >
                            {
                                title: '审计日志',
                                border: false,
                                iconCls:'sjgl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_5]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_BJGL" >
                            {
                                title: '报警管理',
                                border: false,
                                iconCls:'bjgl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_6]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_YXJK" >
                            {
                                title: '运行监控',
                                border: false,
                                iconCls:'yxjk',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_7]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_SJYGL" >
                            {
                                title: '数据源管理',
                                border: false,
                                iconCls:'sjygl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_8]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_YYGL" >
                            {
                                title: '应用管理',
                                border: false,
                                iconCls:'yygl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_9]
                            },
                            </lbs:access>
                            <lbs:access code="TOP_SHGL" >
                            {
                                title: '审核管理',
                                border: false,
                                iconCls:'shgl',
                                bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                                items: [tree_menu_10]
                            },
                            </lbs:access>
                             {}
                        ]
                    });

                    //页面的中间面板
                    centerPanel = new Ext.TabPanel({
                        id: 'mainContent',
                        region: 'center',
                        deferredRender: false,
                        enableTabScroll: true,
                        activeTab: 0,
                        items: []
                    });
                    centerPanel.activate(0);

                    var viewport = new Ext.Viewport({
                        layout: 'border',
                        loadMask: true,
                        items: [northPanel, 		//上
                                westPanel,  		//左
                                centerPanel		//中
                        ]
                    });

                    northBar.get(0).setText("您好！${account.name}");

                    var soundManager = new SoundManager();
                    soundManager.debugMode = false;
                    soundManager.url = 'sound/swf';
                    soundManager.beginDelayedInit();
                    soundManager.onload = function() {
                        soundManager.createSound({
                            id: 'msgSound',
                            url: 'sound/mp3/msg.mp3'
                        });
                    }
                    //检查会话是否超时
                    idx = 0;
                    idx2 = 0;
                    var task = {
                        run : function() {
                            Ext.Ajax.request({
                                url: 'checkTimeout.action',
                                success: function(response){
                                    var result = response.responseText;
                                    if(result!=null&&result.length>0){
                                       alert("会话过期，请重新登录");
                                       location.href="login.jsp";
                                    }
                                }
                            });
                            if(idx==0){
                                Ext.Ajax.request({
                                    url: 'AlertAction_refreshAlerts.action',
                                    success: function(response){
                                        var result = Ext.util.JSON.decode(response.responseText);
                                        if(result.device>0||result.business>0||result.security>0){
                                            var qq = new Ext.ux.ToastWindow({
                                                title: '报警提示',
                                                html: result.time + ' 收到' + result.device+ '条设备报警信息，<br/>'+result.time+' 收到'+result.business+'条业务报警信息，<br/>'+result.time+ ' 收到'+result.security+'条安全报警信息<br><a href="javascript:void(0);" onclick="cacheFresh();">暂时不刷新</a>',
                                                iconCls: 'bjgl',
                                                autoShow:true
                                            });
                                            qq.animShow();
                                            soundManager.play('msgSound');
                                        }
                                    }
                                });
                            } else if (idx>0&&idx<20){
                                idx ++;
                            }else if(idx>=20){
                                idx = 0;
                            }
                            if(idx2==0){
                                Ext.Ajax.request({
                                    url: 'AlertAction_refreshDiskUseAlerts.action',
                                    success: function(response){
                                        var result = Ext.util.JSON.decode(response.responseText);
                                        if(result.alert == 1){
                                            var qq = new Ext.ux.ToastWindow({
                                                title: '报警提示',
                                                html: result.time+' 收到'+result.alert+'条报警信息:审计库容量达到警戒值'+result.dbUsed+'，请看[报警阀值设置]<br/>'+result.diskMsg+'<br><a href="javascript:void(0);" onclick="cacheFresh2();">暂时不刷新</a>',
                                                iconCls: 'bjgl',
                                                autoShow:true
                                            });
                                            qq.animShow();
                                            soundManager.play('msgSound');
                                        }else if(result.alert == 2){
                                            alert("会话过期，请重新登录");
                                            location.href="login.jsp";
                                        }
                                    }
                                });
                            } else if (idx>20&&idx2<20){
                                idx2 ++;
                            }else if(idx2>=20){
                                idx2 = 0;
                            }
                        },
                        interval : 10000
                    };
                    Ext.TaskMgr.start(task);

                });
        function cacheFresh(){
            idx ++;
            return idx;
        }
        function cacheFresh2(){
            idx2 ++;
            return idx2;
        }
        function showWindow(flag){
            <%--if(flag==1){--%>
                <%--window.open("admin/forward.do?m=eqalert");--%>
            <%--}else if(flag==2){--%>
                <%--window.open("admin/forward.do?m=bsalert");--%>
            <%--}else if(flag==3){--%>
                <%--window.open("admin/forward.do?m=scalert");--%>
            <%--}--%>
        }
        /**
         * 设置网站为首页
         * @param obj
         * @param vrl
         * @constructor
         */
        function SetHome(obj,vrl){
            try {
                obj.style.behavior='url(#default#homepage)';obj.setHomePage(vrl);
            } catch(e){
                if(window.netscape) {
                    try {
                        netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
                    }
                    catch (e) {
                        alert("此操作被浏览器拒绝！\n请在浏览器地址栏输入“about:config”并回车\n然后将[signed.applets.codebase_principal_support]设置为'true'");
                    }
                    var prefs = Components.classes['@mozilla.org/preferences-service;1'].getService(Components.interfaces.nsIPrefBranch);
                    prefs.setCharPref('browser.startup.homepage',vrl);
                }
            }
        }

        /**
         * 设置加入收藏夹
         * @param sURL
         * @param sTitle
         * @constructor
         */
        function AddFavorite(sURL, sTitle){
            try {
                window.external.addFavorite(sURL, sTitle);
            } catch (e) {
                try {
                    window.sidebar.addPanel(sTitle, sURL, "");
                } catch (e) {
                    alert("加入收藏失败，请使用Ctrl+D进行添加");
                }
            }
        }
        function logout(){
            Ext.Msg.confirm("确认","确认退出系统吗？",function(btn){
                if (btn == 'yes') {
                    window.location = "logout.action";
                }else{
                    return false;
                }
            });
        }

        Ext.apply(Ext.form.VTypes,{
            //验证方法
            password:function(val,field){//val指这里的文本框值，field指这个文本框组件
                if(field.password.password_id){
                    //password是自定义的配置参数，一般用来保存另外的组件的id值
                    var pwd=Ext.get(field.password.password_id);//取得user_password的那个id的值
                    return (val==pwd.getValue());//验证
                }
                return true;
            },
            //验证提示错误提示信息(注意：方法名+Text)
            passwordText: "两次密码输入不一致!"
         });

        var pwdForm = new Ext.FormPanel({
            region:'center',
            deferredRender:true,
            frame:true,
            border:false,
            labelAlign : 'right',
            defaults:{xtype:"textfield",inputType:"password"},
            items:[{
                fieldLabel : '当前密码',
                name : 'pwd',
                id : 'pwd',
                width : 150
            }, {
                fieldLabel : '输入新密码',
                name : 'newpwd',
                id : 'newpwd',
                width : 150
            }, {
                fieldLabel : '再次输入新密码',
                name : 'rnewpwd',
                id : 'rnewpwd',
                width : 150,
                password:{password_id:'newpwd'},
                vtype:'password'
            }]
        });
        var pwdWin;
        function showUpdatePwd(){
            if(!pwdWin){
                var pwdWin = new Ext.Window({
                    layout:'border',
                    width:310,
                    height:160,
                    closeAction:'hide',
                    plain: true,
                    modal:true,
                    title:'修改密码',
                    resizable:false,

                    items: pwdForm,

                    buttons : [{
                        text : '保存',
                        listeners : {
                            'click' : function() {
                                pwdForm.getForm().submit({
                                    clientValidation : true,
                                    url : 'AccountAction_updatePwd.action',
                                    success : function(form, action) {
                                        Ext.Msg.alert('保存成功', '保存成功！');
                                        pwdWin.close();
                                    },
                                    failure : function(form, action) {
                                        Ext.Msg.alert('保存失败', '系统错误，请联系管理员。');
                                        pwdWin.close();
                                    }
                                });
                            }
                        }
                    }, {
                        text : '取消',
                        listeners : {
                            'click' : function() {
                                pwdWin.close();
                            }
                        }
                    }]

                });

                pwdWin.show();
            }

        }

        function nodeClick2(_url,id,text){
            if (_url != ''){
                if(_url.indexOf('?')>0)
                    _url += '&time=' + new Date().getTime();
                else
                    _url += '?time=' + new Date().getTime();
            }
            var _tab = centerPanel.getComponent(id) ;
            if(!_tab){
                centerPanel.add({
                    id: id ,
                    title: text ,
                    closable: true ,
                    iconCls: '',
                    html: '<iframe id="frame_'+id+'" width="100%" height="100%" frameborder="0" src="'+_url+'"></iframe>'
                }) ;
            }
            centerPanel.setActiveTab(id) ;
        }

    </script>
        </DIV>
    </body>
</html>