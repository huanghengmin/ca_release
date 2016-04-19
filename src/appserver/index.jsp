<%@page contentType="text/html;charset=utf-8" %>
<%@include file="/include/common.jsp" %>
<%@include file="/taglib.jsp" %>

<c:if test="${account==null}">
    <%response.sendRedirect("login.jsp");%>
</c:if>
<html>
<head>
    <title>CA管理中心</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <meta http-equiv="pragma" content="no-cache"/>
    <meta http-equiv="cache-control" content="no-cache"/>
    <meta http-equiv="expires" content="0"/>
    <META http-equiv="x-ua-compatible" content="ie=EmulateIE6"/>
</head>
<body>
<DIV id=top-div>
    <DIV id=funmenu><A onclick="deploy();return false;" href="javascript:void(0);"><IMG src="img/deploy.png">重新部署</A>|
        <A onclick="bak();return false;" href="javascript:void(0);"><IMG src="img/backup.png">备份系统</A>|
        <A onclick="uploadBak();return false;" href="javascript:void(0);"><IMG src="img/upload.png">上传系统恢复包</A>|
        <A onclick="restoreBak();return false;" href="javascript:void(0);"><IMG src="img/restore.png">还原系统</A>|
        <%--<A onclick="setFrontPage();return false;"href="javascript:void(0);"><IMG src="img/house.png">设为首页</A>|--%>
        <A onclick=window.external.AddFavorite(location.href,document.title); href="javascript:void(0);"><IMG
                src="img/page_white_office.png">加入收藏</A>|
        <A onclick="showUpdatePwd();return false;" href="javascript:void(0);"><IMG src="img/key.png">修改密码</A>|
        <A onclick="logout();return false;" href="javascript:void(0);"><IMG src="img/door_out.png">退出系统</A>
    </DIV>
</DIV>
<DIV>
    <script type="text/javascript">
        var centerPanel;
        Ext.onReady(function () {
            Ext.QuickTips.init();
            Ext.form.Field.prototype.msgTarget = 'side';
            var imagePath = 'js/ext/resources/images';
            Ext.BLANK_IMAGE_URL = imagePath + '/default/tree/s.gif';

            var menu_root_node_1 = new Ext.tree.TreeNode({
                text: '权限管理',
                expanded: false
            });
            var menu_root_node_2 = new Ext.tree.TreeNode({
                text: '网络管理',
                expanded: false
            });
            var menu_root_node_3 = new Ext.tree.TreeNode({
                text: '系统管理',
                expanded: false
            });
            var menu_root_node_4 = new Ext.tree.TreeNode({
                text: '审计管理',
                expanded: false
            });

            var menu_root_node_5 = new Ext.tree.TreeNode({
                text: 'CA功能',
                expanded: false
            });

            var menu_root_node_6 = new Ext.tree.TreeNode({
                text: 'RA功能',
                expanded: false
            });

            var menu_root_node_7 = new Ext.tree.TreeNode({
                text: '系统配置',
                expanded: false
            });

            var menu_root_node_8 = new Ext.tree.TreeNode({
                text: '主机监控',
                expanded: false
            });

            var mrn_1_1 = new Ext.tree.TreeNode({
                id: 'mrn_1_1',
                text: '用户管理',
                leaf: true,
                url: 'pages/user/userIndex.jsp'
            });
            var mrn_1_2 = new Ext.tree.TreeNode({
                id: 'mrn_1_2',
                text: '角色管理',
                leaf: true,
                url: 'pages/user/roleIndex.jsp'
            });
            var mrn_1_3 = new Ext.tree.TreeNode({
                id: 'mrn_1_3',
                text: '安全策略',
                leaf: true,
                url: 'pages/user/safePolicy.jsp'
            });
            <lbs:access code="SECOND_YHGL">
            menu_root_node_1.appendChild(mrn_1_1);
            </lbs:access>
            <lbs:access code="SECOND_JSGL">
            menu_root_node_1.appendChild(mrn_1_2);
            </lbs:access>
            <lbs:access code="SECOND_AQCL">
            menu_root_node_1.appendChild(mrn_1_3);
            </lbs:access>

            var mrn_2_1 = new Ext.tree.TreeNode({
                id: 'mrn_2_1',
                text: '接口管理',
                leaf: true,
                url: 'pages/net/manager_interface.jsp'
            });
            var mrn_2_2 = new Ext.tree.TreeNode({
                id: 'mrn_2_2',
                text: '路由管理',
                leaf: true,
                url: 'pages/net/manager_router.jsp'
            });
            var mrn_2_3 = new Ext.tree.TreeNode({
                id: 'mrn_2_3',
                text: '网络测试',
                leaf: true,
                url: 'pages/net/manager_pingTelnet.jsp'
            });
            var mrn_2_4 = new Ext.tree.TreeNode({
                id: 'mrn_2_4',
                text: '安全配置',
                leaf: true,
                url: 'pages/net/manager_security_config.jsp'
            });
            <lbs:access code="SECOND_JKGL">
            menu_root_node_2.appendChild(mrn_2_1);
            </lbs:access>
            <lbs:access code="SECOND_WLCS">
            menu_root_node_2.appendChild(mrn_2_2);
            </lbs:access>
            <lbs:access code="SECOND_LYGL">
            menu_root_node_2.appendChild(mrn_2_3);
            </lbs:access>
            <lbs:access code="SECOND_PZGL">
            menu_root_node_2.appendChild(mrn_2_4);
            </lbs:access>

            var mrn_3_1 = new Ext.tree.TreeNode({
                id: 'mrn_3_1',
                text: '平台说明',
                leaf: true,
                url: 'pages/system/manager_version.jsp'
            });
            var mrn_3_2 = new Ext.tree.TreeNode({
                id: 'mrn_3_2',
                text: '平台管理',
                leaf: true,
                url: 'pages/system/manager_platform.jsp'
            });

            var mrn_3_3 = new Ext.tree.TreeNode({
                id: 'mrn_3_3',
                text: '证书管理',
                leaf: true,
                url: 'pages/system/manager_license.jsp'
            });
            var mrn_3_4 = new Ext.tree.TreeNode({
                id: 'mrn_3_4',
                text: '日志下载',
                leaf: true,
                url: 'pages/system/manager-downloadLog.jsp'
            });

            var mrn_3_5 = new Ext.tree.TreeNode({
                id: 'mrn_3_5',
                text: '版本升级',
                leaf: true,
                url: 'pages/system/manager_upgrade_version.jsp'
            });

            <lbs:access code="SECOND_PTSM">
            menu_root_node_3.appendChild(mrn_3_1);
            </lbs:access>
            <lbs:access code="SECOND_PTGL">
            menu_root_node_3.appendChild(mrn_3_2);
            </lbs:access>
            <lbs:access code="SECOND_ZSGL">
            menu_root_node_3.appendChild(mrn_3_3);
            </lbs:access>
            <lbs:access code="SECOND_RZXZ">
            menu_root_node_3.appendChild(mrn_3_4);
            </lbs:access>
            <lbs:access code="SECOND_BBSJ">
            menu_root_node_3.appendChild(mrn_3_5);
            </lbs:access>

            var mrn_4_1 = new Ext.tree.TreeNode({
                id: 'mrn_4_1',
                text: '管理员日志',
                leaf: true,
                url: 'pages/audit/audit_user.jsp'
            });

            <lbs:access code="SECOND_GLRZ">
            menu_root_node_4.appendChild(mrn_4_1);
            </lbs:access>

            var mrn_5_2 = new Ext.tree.TreeNode({
                id: 'mrn_5_2',
                text: 'CA配置',
                leaf: true,
                url: 'pages/x509ca/x509ca.jsp'
            });

            var mrn_5_3 = new Ext.tree.TreeNode({
                id: 'mrn_5_3',
                text: 'CA信息',
                leaf: true,
                url: 'pages/x509ca/x509caview.jsp'
            });

            <lbs:access code="SECOND_CAPZ">
            menu_root_node_5.appendChild(mrn_5_2);
            </lbs:access>
            <lbs:access code="SECOND_CAXX">
            menu_root_node_5.appendChild(mrn_5_3);
            </lbs:access>

            var mrn_6_1 = new Ext.tree.TreeNode({
                id: 'mrn_6_1',
                text: '用户证书管理',
                leaf: true,
                url: 'pages/x509user/x509user.jsp'
            });

            var mrn_6_2 = new Ext.tree.TreeNode({
                id: 'mrn_6_2',
                text: '设备证书管理',
                leaf: true,
                url: 'pages/x509server/x509server.jsp'
            });

            <lbs:access code="SECOND_YHZZ">
            menu_root_node_6.appendChild(mrn_6_1);
            </lbs:access>
            <lbs:access code="SECOND_SBZZ">
            menu_root_node_6.appendChild(mrn_6_2);
            </lbs:access>

            var mrn_7_1 = new Ext.tree.TreeNode({
                id: 'mrn_7_1',
                text: 'LDAP 配置',
                leaf: true,
                url: 'pages/ldap/ldap_config.jsp'
            });

            var mrn_7_2 = new Ext.tree.TreeNode({
                id: 'mrn_7_2',
                text: '日志服务器',
                leaf: true,
                url: 'pages/syslog/syslog_config.jsp'
            });

//    var mrn_7_3 = new Ext.tree.TreeNode({
//        id: 'mrn_7_3',
//        text: '策略配置',
//        leaf: true,
//        url: 'pages/strategy/strategy.jsp'
//    });

            <lbs:access code="SECOND_LDAP">
            menu_root_node_7.appendChild(mrn_7_1);
            </lbs:access>

            <lbs:access code="SECOND_RZZJ">
            menu_root_node_7.appendChild(mrn_7_2);
            </lbs:access>

            <%--<lbs:access code="SECOND_STRATEGY">--%>
            <%--menu_root_node_7.appendChild(mrn_7_3);--%>
            <%--</lbs:access>--%>


            var mrn_8_1 = new Ext.tree.TreeNode({
                id: 'mrn_8_1',
                text: '主机监控',
                leaf: true,
                url: 'pages/host/myjfreezhexian.jsp'
            });

            <lbs:access code="SECOND_ZJJK">
            menu_root_node_8.appendChild(mrn_8_1);
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

            function nodeClick(node, e) {
                if (node.isLeaf()) {
                    var _url = node.attributes.url;
                    if (_url != '') {
                        if (_url.indexOf('?') > 0)
                            _url += '&time=' + new Date().getTime();
                        else
                            _url += '?time=' + new Date().getTime();
                    }
                    var _tab = centerPanel.getComponent(node.id);
                    if (!_tab) {
                        centerPanel.removeAll();
                        centerPanel.add({
                            id: node.id,
                            title: node.text,
                            closable: true,
                            iconCls: node.attributes.iconCls,
                            html: '<iframe id="frame_' + node.id + '" width="100%" height="100%" frameborder="0" src="' + _url + '"></iframe>',
                            listeners: {      //增加点击页面自动刷新功能
                                show: function () {
                                    var mID = centerPanel.getActiveTab().getId();
                                    if (centerPanel.getActiveTab().getStateId() == null) {
                                        window.frames[0].location.reload();
                                    } else {
                                        if (window.parent.document.getElementById('frame_' + mID) != null) {
                                            if (mID == "mrn_8_2") {

                                            } else {
                                                window.parent.document.getElementById('frame_' + mID).contentWindow.location.reload();
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    centerPanel.setActiveTab(node.id);
                }
            }

            var northBar = new Ext.Toolbar({
                id: 'northBar',
                items: [
                    {
                        xtype: 'tbtext',
                        id: 'msg_title',
                        text: ''
                    },
                    {
                        xtype: "tbfill"
                    },
                    {
                        id: 'warningMsg',
                        iconCls: 'warning',
                        hidden: true,
                        handler: function () {
                            eastPanel.expand(true);
                        }
                    },
                    {
                        xtype: 'tbseparator'
                    },
                    {
                        pressed: false,
                        text: '刷新',
                        iconCls: 'refresh',
                        handler: function () {
                            var mID = centerPanel.getActiveTab().getId();
                            if (centerPanel.getActiveTab().getStateId() == null) {
                                window.frames[0].location.reload();
                            } else {
                                window.parent.document.getElementById('frame_' + mID).contentWindow.location.reload();
                            }
                        }
                    },
                    {
                        xtype: 'tbseparator'
                    },
                    {
                        pressed: false,
                        text: '帮助',
                        iconCls: 'help',
                        handler: function () {
                            window.open('help.doc');
                        }
                        /*},{
                         xtype: 'tbseparator'
                         },{
                         xtype:"combo",
                         width: 120*/
                    }
                ]
            });

            //页面的上部分
            var northPanel = new Ext.Panel({
                region: 'north', //北部，即顶部，上面
                contentEl: 'top-div', //面板包含的内容
                split: false,
                titlebar: false,
                border: false, //是否显示边框
                collapsible: false, //是否可以收缩,默认不可以收缩，即不显示收缩箭头
                height: 86,
                bbar: northBar
            });

            //左边菜单
            var westPanel = new Ext.Panel({
                title: '系统功能', //面板名称
                region: 'west', //该面板的位置，此处是西部 也就是左边
                split: true, //为true时，布局边框变粗 ,默认为false
                titlebar: true,
                collapsible: true,
                animate: true,
                border: true,
                bodyStyle: 'border-bottom: 0px solid;',
                bodyborder: true,
                width: 200,
                minSize: 100, //最小宽度
                maxSize: 300,
                layout: 'accordion',
                iconCls: 'title-1',
                layoutConfig: {             //布局
                    titleCollapse: true,
                    animate: true
                },
                items: [
                    <lbs:access code="TOP_QXGL" >
                    {
                        title: '权限管理',
                        border: false,
                        iconCls: 'user',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_1]
                    },
                    </lbs:access>
                    <lbs:access code="TOP_WLGL" >
                    {
                        title: '网络管理',
                        border: false,
                        iconCls: 'wlgl',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_2]
                    },
                    </lbs:access>
                    <lbs:access code="TOP_XTGL" >
                    {
                        title: '系统管理',
                        border: false,
                        iconCls: 'system',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_3]
                    },
                    </lbs:access>
                    <lbs:access code="TOP_SJGL" >
                    {
                        title: '审计管理',
                        border: false,
                        iconCls: 'audit',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_4]
                    },
                    </lbs:access>

                    <lbs:access code="TOP_CAGN" >
                    {
                        title: 'CA功能',
                        border: false,
                        iconCls: 'cacert',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_5]
                    },
                    </lbs:access>

                    <lbs:access code="TOP_RAGN" >
                    {
                        title: 'RA功能',
                        border: false,
                        iconCls: 'ssl',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_6]
                    },
                    </lbs:access>

                    <lbs:access code="TOP_XTPZ" >
                    {
                        title: '系统配置',
                        border: false,
                        iconCls: 'setting',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_7]
                    },
                    </lbs:access>

                    <lbs:access code="TOP_JKGL" >
                    {
                        title: '监控管理',
                        border: false,
                        iconCls: 'monitor',
                        bodyStyle: 'border-bottom: 1px solid;padding-top: 5px;padding-left: 15px;',
                        items: [tree_menu_8]
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
                items: [northPanel, //上
                    westPanel, //左
                    centerPanel        //中
                ]
            });

            northBar.get(0).setText("您好！${account.name}");
            //检查会话是否超时
            var task = {
                run: function () {
                    Ext.Ajax.request({
                        url: 'checkTimeout.action?time=' + new Date().getTime(),
                        success: function (response) {
                            var result = response.responseText;
                            if (result != null && result.length > 0) {
                                alert("会话过期，请重新登录");
                                location.href = "login.jsp";
                            }

                        }
                    });
                },
                interval: 10000
            };
            Ext.TaskMgr.start(task);
        });

        function showWindow(flag) {
            <%--if(flag==1){--%>
            <%--window.open("admin/forward.do?m=eqalert");--%>
            <%--}else if(flag==2){--%>
            <%--window.open("admin/forward.do?m=bsalert");--%>
            <%--}else if(flag==3){--%>
            <%--window.open("admin/forward.do?m=scalert");--%>
            <%--}--%>
        }

        function logout() {
            Ext.Msg.confirm("确认", "确认退出系统吗？", function (btn) {
                if (btn == 'yes') {
                    window.location = "logout.action";
                } else {
                    return false;
                }
            });
        }

        Ext.apply(Ext.form.VTypes, {
            //验证方法
            password: function (val, field) {//val指这里的文本框值，field指这个文本框组件
                if (field.password.password_id) {
                    //password是自定义的配置参数，一般用来保存另外的组件的id值
                    var pwd = Ext.get(field.password.password_id);//取得user_password的那个id的值
                    return (val == pwd.getValue());//验证
                }
                return true;
            },
            //验证提示错误提示信息(注意：方法名+Text)
            passwordText: "两次密码输入不一致!"
        });

        var pwdForm = new Ext.FormPanel({
            region: 'center',
            deferredRender: true,
            frame: true,
            border: false,
            labelAlign: 'right',
            defaults: {xtype: "textfield", inputType: "password"},
            items: [
                {
                    fieldLabel: '当前密码',
                    name: 'pwd',
                    id: 'pwd',
                    width: 150
                },
                {
                    fieldLabel: '输入新密码',
                    name: 'newpwd',
                    id: 'newpwd',
                    width: 150
                },
                {
                    fieldLabel: '再次输入新密码',
                    name: 'rnewpwd',
                    id: 'rnewpwd',
                    width: 150,
                    password: {password_id: 'newpwd'},
                    vtype: 'password'
                }
            ]
        });
        var pwdWin;
        function showUpdatePwd() {
            if (!pwdWin) {
                var pwdWin = new Ext.Window({
                    layout: 'border',
                    width: 310,
                    height: 160,
                    closeAction: 'hide',
                    plain: true,
                    modal: true,
                    title: '修改密码',
                    resizable: false,

                    items: pwdForm,

                    buttons: [
                        {
                            text: '保存',
                            listeners: {
                                'click': function () {
                                    pwdForm.getForm().submit({
                                        clientValidation: true,
                                        url: 'AccountAction_updatePwd.action',
                                        success: function (form, action) {
                                            Ext.Msg.alert('保存成功', '保存成功！');
                                            pwdWin.close();
                                        },
                                        failure: function (form, action) {
                                            Ext.Msg.alert('保存失败', '系统错误，请联系管理员。');
                                            pwdWin.close();
                                        }
                                    });
                                }
                            }
                        },
                        {
                            text: '取消',
                            listeners: {
                                'click': function () {
                                    pwdWin.close();
                                }
                            }
                        }
                    ]

                });

                pwdWin.show();
            }

        }

        function nodeClick2(_url, id, text) {
            if (_url != '') {
                if (_url.indexOf('?') > 0)
                    _url += '&time=' + new Date().getTime();
                else
                    _url += '?time=' + new Date().getTime();
            }
            var _tab = centerPanel.getComponent(id);
            if (!_tab) {
                centerPanel.add({
                    id: id,
                    title: text,
                    closable: true,
                    iconCls: '',
                    html: '<iframe id="frame_' + id + '" width="100%" height="100%" frameborder="0" src="' + _url + '"></iframe>'
                });
            }
            centerPanel.setActiveTab(id);
        }


        function deploy() {
            Ext.Msg.confirm("警告", "是否重新部署?,重新部署会清空所有原始数据!", function (sid) {
                if (sid == "yes") {
                    Ext.Ajax.request({
                        url: 'DeployAction_deploy.action',
                        timeout: 20 * 60 * 1000,
                        method: 'POST',
                        success: function (response, options) {
                            var o = Ext.util.JSON.decode(response.responseText);
                            Ext.Msg.confirm("消息", o.msg, function (sid) {
                                if (sid == "yes") {
                                    Ext.Ajax.request({
                                        url: 'DeployAction_upgradeService.action',
                                        timeout: 20 * 60 * 1000,
                                        method: 'POST',
                                        success: function (response, options) {
                                            Ext.Msg.alert('消息', "服务重启中........!");
                                        },
                                        failure: function (response, options) {
                                            Ext.Msg.alert('消息', "服务未正常重启!");
                                        }
                                    });
                                } else {
                                    Ext.Ajax.request({
                                        url: 'DeployAction_admin.action',
                                        timeout: 20 * 60 * 1000,
                                        method: 'POST',
                                        success: function (response, options) {
                                            Ext.Msg.alert('消息', "系统未重新部署,重新登陆管理界面查看!");
                                        },
                                        failure: function (response, options) {
                                            Ext.Msg.alert('消息', "回滚部署操作失败!");
                                        }
                                    });
                                }
                            });
                        },
                        failure: function (response, options) {
                            var o = Ext.util.JSON.decode(response.responseText);
                            Ext.Msg.alert('消息', o.msg);
                        }
                    });
                }
            });
        }


        function bak() {
            Ext.Msg.confirm("消息", "是否备份?", function (sid) {
                if (sid == "yes") {
                    Ext.Ajax.request({
                        url: 'BakAction_bak.action',
                        timeout: 20 * 60 * 1000,
                        method: 'POST',
                        success: function (response, options) {
                            var o = Ext.util.JSON.decode(response.responseText);
                            Ext.Msg.alert('消息', o.msg);
                        },
                        failure: function (response, options) {
                            var o = Ext.util.JSON.decode(response.responseText);
                            Ext.Msg.alert('消息', o.msg);
                        }
                    });
                }
            });
        }

        function uploadBak() {
            var form = new Ext.form.FormPanel({
                baseCls: 'x-plain',
                labelWidth: 150,
                labelAlign: 'right',
                fileUpload: true,
                defaultType: 'textfield',
                defaults: {
                    anchor: '95%',
                    allowBlank: false,
                    blankText: '该项不能为空！'
                },
                items: [
                    {
                        id: 'uploadFile',
                        allowBlank: false,
                        name: 'uploadFile',
                        fieldLabel: '系统恢复包',
                        xtype: 'textfield',
                        inputType: 'file',
                        editable: false
                    },
                ]
            });

            var win = new Ext.Window({
                title: '上传系统恢复包',
                width: 500,
                height: 300,
                layout: 'fit',
                plain: true,
                bodyStyle: 'padding:5px;',
                buttonAlign: 'center',
                items: form,
                bbar: [
                    '->', {
                        text: '上传系统恢复包',
                        id: 'uploadBak.submit',
                        handler: function () {
                            if (form.getForm().isValid()) {
                                form.getForm().submit({
                                    url: 'BakAction_uploadBak.action',
                                    timeout: 20 * 60 * 1000,
                                    method: "POST",
                                    waitTitle: '系统提示',
                                    waitMsg: '正在上传...',
                                    success: function (form, action) {
                                        Ext.MessageBox.alert("提示", action.result.msg);
                                        store.reload();
                                        win.close();
                                    },
                                    failure: function (form, action) {
                                        var msg = action.result.msg;
                                        Ext.MessageBox.show({
                                            title: '信息',
                                            width: 250,
                                            msg: msg,
                                            buttons: Ext.MessageBox.OK,
                                            buttons: {'ok': '确定'},
                                            icon: Ext.MessageBox.ERROR,
                                            closable: false
                                        });
                                    }
                                });
                            }
                        }
                    }, {
                        text: '关闭',
                        handler: function () {
                            win.close();
                        }
                    }]
            });
            win.show();
        }


        function restoreBak() {
            Ext.Msg.confirm("消息", "是否还原系统到备份点?", function (sid) {
                if (sid == "yes") {
                    Ext.Ajax.request({
                        url: 'BakAction_bakRestore.action',
                        timeout: 20 * 60 * 1000,
                        method: 'POST',
                        success: function (response, options) {
                            var o = Ext.util.JSON.decode(response.responseText);
                            Ext.Msg.alert('消息', o.msg);
                        },
                        failure: function (response, options) {
                            var o = Ext.util.JSON.decode(response.responseText);
                            Ext.Msg.alert('消息', o.msg);
                        }
                    });
                }
            });
        }

    </script>
</DIV>
</body>

</html>