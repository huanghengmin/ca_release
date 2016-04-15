Ext.onReady(function () {
    Ext.BLANK_IMAGE_URL = '../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';

    var province_store = new Ext.data.Store({
        reader: new Ext.data.JsonReader({
            fields: ["id", "districtName"],
            totalProperty: 'totalCount',
            root: 'root'
        })
    });

 /*   var city_store = new Ext.data.Store({
        reader: new Ext.data.JsonReader({
            fields: ["id", "districtName"],
            totalProperty: 'totalCount',
            root: 'root'
        })
    });*/

    var keyBits = [
        ['1024', '1024 bits'],
        ['2048', '2048 bits'],
        ['4096', '4096 bits']
    ];


    var formPanel = new Ext.form.FormPanel({
        plain:true,
        width:500,
        labelAlign:'right',
        labelWidth:120,
        defaultType:'textfield',
        defaults:{
            width:250,
            anchor:'95%',
            allowBlank:false,
            blankText:'该项不能为空!'
        },
        items:[
            new Ext.form.TextField({
                fieldLabel: '通用名',
                name: 'x509Ca.cn',
                emptyText:"请输入用户姓名",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                id: 'msg.x509Ca.cn',
                allowBlank: false,
                blankText: "不能为空，请正确填写",
                listeners: {
                    blur: function () {
                        var thisCommon = Ext.getCmp("msg.x509Ca.cn");
                        var cn = thisCommon.getValue();
                        Ext.Ajax.request({
                            url: '../../X509CaAction_existCa.action',
                            timeout: 20 * 60 * 1000,
                            method: 'post',
                            params: {
                                cn: cn
                            },
                            success: function (r, o) {
                                var respText = Ext.util.JSON.decode(r.responseText);
                                var msg = respText.msg;
                                if (msg == 'false') {
                                    Ext.MessageBox.show({
                                        title: '信息',
                                        width: 250,
                                        msg: '已存在数据,请更换通用名!',
                                        buttons: Ext.MessageBox.OK,
                                        buttons: {'ok': '确定'},
                                        icon: Ext.MessageBox.INFO,
                                        closable: false,
                                        fn: function (e) {
                                            if (e == 'ok') {
                                                Ext.getCmp('msg.x509Ca.cn').setValue('');
                                            }
                                        }
                                    });
                                }
                            }
                        });
                    }
                }
            }),
            new Ext.form.ComboBox({
                mode: 'remote',// 指定数据加载方式，如果直接从客户端加载则为local，如果从服务器断加载// 则为remote.默认值为：remote
                border: true,
                frame: true,
                pageSize: 10,// 当元素加载的时候，如果返回的数据为多页，则会在下拉列表框下面显示一个分页工具栏，该属性指定每页的大小
                // 在点击分页导航按钮时，将会作为start及limit参数传递给服务端，默认值为0，只有在mode='remote'的时候才能够使用
                editable: false,
                fieldLabel: '省/行政区',
                emptyText: '请选择所在省/行政区',
                id: 'msg.x509User.province',
//                hiddenName : 'x509Ca.province',
                triggerAction: "all",// 是否开启自动查询功能
                store: province_store,// 定义数据源
                valueField: "districtName", // 关联某一个逻辑列名作为显示值
                displayField: "districtName", // 关联某一个逻辑列名作为显示值
//                valueField: "id", // 关联某一个逻辑列名作为实际值
                //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                name: 'x509Ca.province',
                allowBlank: false,
                blankText: "请选择所在省/行政区",
                listeners: {
                   /* select: function () {
                        var value = this.getValue();
                        city_store.proxy = new Ext.data.HttpProxy({
                            url: "../../DistrictAction_findCity.action?parentId=" + value
                        })
                        city_store.load();
                    },*/
                    render: function () {
                        province_store.proxy = new Ext.data.HttpProxy({
                            url: '../../DistrictAction_findProvince.action',
                            method: "POST"
                        })
                    }
                }
            }),
            /*new Ext.form.ComboBox({
                mode: 'remote',// 指定数据加载方式，如果直接从客户端加载则为local，如果从服务器断加载// 则为remote.默认值为：remote
                border: true,
                frame: true,
                pageSize: 10,// 当元素加载的时候，如果返回的数据为多页，则会在下拉列表框下面显示一个分页工具栏，该属性指定每页的大小
                // 在点击分页导航按钮时，将会作为start及limit参数传递给服务端，默认值为0，只有在mode='remote'的时候才能够使用
                editable: false,
                fieldLabel: '城市/乡镇',
                emptyText: '请选择所在城市/乡镇',
                id: 'x509Ca.msg.city',
//                hiddenName: 'x509Ca.orgCode',
                triggerAction: "all",// 是否开启自动查询功能
                store: city_store,// 定义数据源
                displayField: "districtName", // 关联某一个逻辑列名作为显示值
                valueField: "id", // 关联某一个逻辑列名作为实际值
                //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                name: 'x509Ca.city',
//                hiddenName: 'x509Ca.city',
                allowBlank: false,
                blankText: "请选择所在城市/乡镇"
            }),*/
            new Ext.form.TextField({
                fieldLabel: '城市/乡镇',
                name: 'x509Ca.city',
                emptyText:"请输入所在城市/乡镇",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                id: 'msg.x509Ca.city',
                allowBlank: false,
                blankText: "不能为空，请正确填写所在城市/乡镇"
            }),
            new Ext.form.ComboBox({
                fieldLabel:'密钥位数',
                emptyText:'请选择密钥位数',
                typeAhead:true,
                triggerAction:'all',
                forceSelection:true,
                id:"msg.x509Ca.keyLength",
                mode:'local',
                hiddenName:"x509Ca.keyLength",
                store:new Ext.data.ArrayStore({
                    fields:[
                        'id',
                        'name'
                    ],
                    data:keyBits
                }),
                valueField:'id', //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField:'name'//下拉框显示内容
            }),
            {
                xtype:'textfield',
                fieldLabel:'有效期(天)',
                allowBlank:false,
                value:3650,
                name:'x509Ca.validity',
                id:'msg.x509Ca.validity',
                listeners:{
                    render:function () {
                        Ext.getCmp('msg.x509Ca.validity').setReadOnly(true);
                    }
                }
            }
        ],
        buttons:[
            '->',
            {
                id:'insert_win.info',
                text:'CA签发',
                handler:function () {
                    if (formPanel.form.isValid()) {
                        formPanel.getForm().submit({
                            url:"../../X509CaAction_selfSign.action",
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
            title:'颁发机构信息',
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


