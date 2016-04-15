Ext.onReady(function () {
    Ext.BLANK_IMAGE_URL = '../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';
    var record = new Ext.data.Record.create([
        {name:'host', mapping:'host'} ,
        {name:'port', mapping:'port'} ,
        {name:'base', mapping:'base'},
        {name:'adm', mapping:'adm'},
        {name:'pwd', mapping:'pwd'}
    ]);

    var proxy = new Ext.data.HttpProxy({
        url:"../../LdapConfigAction_find.action"
    });

    var reader = new Ext.data.JsonReader({
        totalProperty:"totalCount",
        root:"root"
    }, record);

    var store = new Ext.data.GroupingStore({
        id:"store.info",
        proxy:proxy,
        reader:reader
    });

    store.load();
    store.on('load',function(){
        var host = store.getAt(0).get('host');
        var port = store.getAt(0).get('port');
        var base = store.getAt(0).get('base');
        var adm = store.getAt(0).get('adm');
        var pwd = store.getAt(0).get('pwd');
        Ext.getCmp('ldap.host').setValue(host);
        Ext.getCmp('ldap.port').setValue(port);
        Ext.getCmp('ldap.adm').setValue(adm);
        Ext.getCmp('ldap.base').setValue(base);
        Ext.getCmp('ldap.pwd').setValue(pwd);
    });


    var formPanel = new Ext.form.FormPanel({
        plain:true,
        width:500,
        labelAlign:'right',
        labelWidth:200,
        defaultType:'textfield',
        defaults:{
            width:250,
            allowBlank:false,
            blankText:'该项不能为空!'
        },
        items:[
            new Ext.form.TextField({
                fieldLabel : 'LDAP服务器IP',
                name : 'host',
                regex:/^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){3}$/,
                regexText:'请输入正确的IP地址',
                id:"ldap.host",
                allowBlank : false,
                blankText : "不能为空，请正确填写"
            }),
            new Ext.form.TextField({
                fieldLabel : 'LDAP服务器端口',
                id:"ldap.port",
                regex:/^(6553[0-6]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[1-9])$/,
                regexText:'请输入正确的端口',
                name : 'port',
                allowBlank : false,
                blankText : "不能为空，请正确填写"
            }),
            new Ext.form.TextField({
                fieldLabel:'LDAP发布DN',
                name:'base',
                id:"ldap.base",
                allowBlank:false,
                blankText:"LDAP发布DN"
            }),
            new Ext.form.TextField({
                fieldLabel:'LDAP登陆DN',
                name:'adm',
                allowBlank:false,
                id:"ldap.adm",
                blankText:"LDAP登陆DN"
            }) ,
            new Ext.form.TextField({
                fieldLabel:'LDAP登陆密码',
                name:'pwd',
                id:"ldap.pwd",
                inputType:'password',
                allowBlank:false,
                blankText:"LDAP登陆密码"
            })
        ],
        buttons:[
           '->',
            {
                id:'insert_win.info',
                text:'保存配置',
                handler:function () {
                    if (formPanel.form.isValid()) {
                        formPanel.getForm().submit({
                            url:"../../LdapConfigAction_save.action",
                            method:'POST',
                            waitTitle:'系统提示',
                            waitMsg:'正在连接...',
                            success:function () {
                                Ext.MessageBox.show({
                                    title:'信息',
                                    width:250,
                                    msg:'保存成功,点击返回页面!',
                                    buttons:Ext.MessageBox.OK,
                                    buttons:{'ok':'确定'},
                                    icon:Ext.MessageBox.INFO,
                                    closable:false
                                });
                            },
                            failure:function () {
                                Ext.MessageBox.show({
                                    title:'信息',
                                    width:250,
                                    msg:'保存失败，请与管理员联系!',
                                    buttons:Ext.MessageBox.OK,
                                    buttons:{'ok':'确定'},
                                    icon:Ext.MessageBox.ERROR,
                                    closable:false
                                });
                            }
                        });
                    } else {
                        Ext.MessageBox.show({
                            title:'信息',
                            width:200,
                            msg:'请填写完成再提交!',
                            buttons:Ext.MessageBox.OK,
                            buttons:{'ok':'确定'},
                            icon:Ext.MessageBox.ERROR,
                            closable:false
                        });
                    }
                }
            },
            {
                text:'测试ldap连接',
                handler:function () {
                    formPanel.getForm().submit({
                        url:"../../LdapConfigAction_ldapConnections.action",
                        method:'POST',
                        waitTitle:'系统提示',
                        waitMsg:'正在连接...',
                        success:function () {
                            Ext.MessageBox.show({
                                title:'信息',
                                width:250,
                                msg:'LDAP服务器已连通!',
                                buttons:Ext.MessageBox.OK,
                                buttons:{'ok':'确定'},
                                icon:Ext.MessageBox.INFO
                            });
                        },
                        failure:function () {
                            Ext.MessageBox.show({
                                title:'信息',
                                width:250,
                                msg:'LDAP服务器连通失败!',
                                buttons:Ext.MessageBox.OK,
                                buttons:{'ok':'确定'},
                                icon:Ext.MessageBox.ERROR,
                                closable:false
                            });
                        }
                    });
                }
            }
        ]
    });

    var panel = new Ext.Panel({
        plain:true,
        width:600,
        border:false,
        items:[{
            id:'panel.info',
            xtype:'fieldset',
            title:'LDAP配置',
            width:530,
            items:[formPanel]
        }]
    });
    new Ext.Viewport({
        layout :'fit',
        renderTo:Ext.getBody(),
        autoScroll:true,
        items:[{
            frame:true,
            autoScroll:true,
            items:[panel]
        }]
    });

});


