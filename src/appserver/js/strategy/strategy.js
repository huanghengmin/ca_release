Ext.onReady(function () {
    Ext.BLANK_IMAGE_URL = '../../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';
    var record = new Ext.data.Record.create([
        {name: 'threeYards', mapping: 'threeYards'},
        {name: 'vpn_ip', mapping: 'vpn_ip'} ,
        {name:'vpn_port',mapping:'vpn_port'}
    ]);

    var proxy = new Ext.data.HttpProxy({
        url: "../../StrategyAction_findConfig.action"
    });

    var reader = new Ext.data.JsonReader({
        totalProperty: "totalCount",
        root: "root"
    }, record);

    var store = new Ext.data.GroupingStore({
        id: "store.info",
        proxy: proxy,
        reader: reader
    });

    store.load();
    store.on('load', function () {
        var vpn_ip = store.getAt(0).get('vpn_ip');
        var vpn_port = store.getAt(0).get('vpn_port');
        var threeYards = store.getAt(0).get('threeYards');
        Ext.getCmp('strategy.vpn_ip').setValue(vpn_ip);
        Ext.getCmp('strategy.vpn_port').setValue(vpn_port);
        Ext.getCmp('strategy.threeYards').setValue(threeYards);
    });

    var formPanel = new Ext.form.FormPanel({
        plain: true,
        width: 500,
        labelAlign: 'right',
        labelWidth: 200,
        defaultType: 'textfield',
        items: [
            {
                xtype: 'fieldset',
                title: '三码合一校验',
                width: 500,
                items: [new Ext.form.Checkbox({
                    inputValue: 1,
                    fieldLabel: '启用三码合一校验',
                    id: "strategy.threeYards",
                    regexText: '启用三码合一校验',
                    name: 'threeYards',
                    blankText: "启用三码合一校验"
                })]
            },
            new Ext.form.TextField({
                fieldLabel: 'VPN服务器地址',
                name: 'vpn_ip',
                regex: /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){3}$/,
                regexText: '请输入正确的IP地址',
                id: "strategy.vpn_ip",
                allowBlank: false,
                blankText: "VPN服务器地址"
            }),
            new Ext.form.TextField({
                fieldLabel: 'VPN服务器端口',
                name: 'vpn_port',
                id: "strategy.vpn_port",
                regex: /^(6553[0-6]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[1-9])$/,
                regexText: '请输入正确的端口',
                allowBlank: false,
                value: "80",
                blankText: "VPN服务器端口"
            })
        ],
        buttons: [
            '->',
            {
                id: 'insert_win.info',
                text: '保存配置',
                handler: function () {
                    if (formPanel.form.isValid()) {
                        formPanel.getForm().submit({
                            url: "../../StrategyAction_strategy.action",
                            method: 'POST',
                            waitTitle: '系统提示',
                            waitMsg: '正在连接...',
                            success: function () {
                                Ext.MessageBox.show({
                                    title: '信息',
                                    width: 250,
                                    msg: '保存成功,点击返回页面!',
                                    buttons: Ext.MessageBox.OK,
                                    buttons: {'ok': '确定'},
                                    icon: Ext.MessageBox.INFO,
                                    closable: false
                                });
                            },
                            failure: function () {
                                Ext.MessageBox.show({
                                    title: '信息',
                                    width: 250,
                                    msg: '保存失败，请与管理员联系!',
                                    buttons: Ext.MessageBox.OK,
                                    buttons: {'ok': '确定'},
                                    icon: Ext.MessageBox.ERROR,
                                    closable: false
                                });
                            }
                        });
                    } else {
                        Ext.MessageBox.show({
                            title: '信息',
                            width: 200,
                            msg: '请填写完成再提交!',
                            buttons: Ext.MessageBox.OK,
                            buttons: {'ok': '确定'},
                            icon: Ext.MessageBox.ERROR,
                            closable: false
                        });
                    }
                }
            }
        ]
    });

    var panel = new Ext.Panel({
        plain: true,
        width: 600,
        border: false,
        items: [{
            id: 'panel.info',
            xtype: 'fieldset',
            title: '策略配置',
            width: 530,
            items: [formPanel]
        }]
    });
    new Ext.Viewport({
        layout: 'fit',
        renderTo: Ext.getBody(),
        autoScroll: true,
        items: [{
            frame: true,
            autoScroll: true,
            items: [panel]
        }]
    });

});


