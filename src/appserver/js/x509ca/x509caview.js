Ext.onReady(function () {
    Ext.BLANK_IMAGE_URL = '../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';


    var record = new Ext.data.Record.create([
        {name: 'cn', mapping: 'cn'},
        {name: 'pwd', mapping: 'pwd'} ,
        {name: 'dn', mapping: 'dn'},
        {name: 'orgCode', mapping: 'orgCode'},
        {name: 'serial', mapping: 'serial'},
        {name: 'keyLength', mapping: 'keyLength'},
        {name: 'province', mapping: 'province'},
        {name: 'city', mapping: 'city'},
        {name: 'certType', mapping: 'certType'},
        {name: 'validity', mapping: 'validity'},
        {name: 'createDate', mapping: 'createDate'},
        {name: 'endDate', mapping: 'endDate'},
        {name: 'organization', mapping: 'organization'},
        {name: 'institution', mapping: 'institution'},
        {name: 'issueCa', mapping: 'issueCa'},
        {name: 'desc', mapping: 'desc'},
        {name: 'certStatus', mapping: 'certStatus'}
    ]);

    var proxy = new Ext.data.HttpProxy({
        url: "../../X509CaAction_findSelf.action"
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
        var cn = store.getAt(0).get('cn');
        var province = store.getAt(0).get('province');
        var city = store.getAt(0).get('city');
        var keyLength = store.getAt(0).get('keyLength');
        var dn = store.getAt(0).get('dn');
        var createDate = store.getAt(0).get('createDate');
        var endDate = store.getAt(0).get('endDate');
        var serial = store.getAt(0).get('serial');
//        var validity = store.getAt(0).get('validity');
        Ext.getCmp('tab.x509Ca.cn').setValue(cn);
        Ext.getCmp('tab.x509Ca.province').setValue(province);
        Ext.getCmp('tab.x509Ca.city').setValue(city);
        Ext.getCmp('tab.x509Ca.keyLength').setValue(keyLength);
//        Ext.getCmp('tab.x509Ca.validity').setValue(validity+" 天");
//        Ext.getCmp('tab.x509Ca.subject').setValue(dn);
        Ext.getCmp('tab.x509Ca.serial').setValue(serial);
        Ext.getCmp('tab.x509Ca.start').setValue(createDate);
        Ext.getCmp('tab.x509Ca.end').setValue(endDate);
    });


    var tab = new Ext.form.FormPanel({
        plain: true,
        labelAlign: 'right',
        labelWidth: 150,
        layout: 'form',
//        style : 'text-align:center',
        defaultType: 'textfield',
        defaults: {
            anchor: '95%',
            allowBlank: false,
            blankText: '该项不能为空!'
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '通用名',
                id: 'tab.x509Ca.cn'
            }),
        /*    new Ext.form.DisplayField({
                fieldLabel: '主题',
                id: 'tab.x509Ca.subject'
            }),*/
            new Ext.form.DisplayField({
                fieldLabel: '省/行政区',
                id: 'tab.x509Ca.province'
            }),
            new Ext.form.DisplayField({
                fieldLabel: '城市/乡镇',
                id: 'tab.x509Ca.city'
            }),
            new Ext.form.DisplayField({
                fieldLabel: '密钥位数',
                id: 'tab.x509Ca.keyLength'
            }),
          /*  new Ext.form.DisplayField({
                fieldLabel: '有效期',
                id: 'tab.x509Ca.validity'
            }),*/
            /* new Ext.form.DisplayField({
             fieldLabel: '版本',
             id: 'tab.x509Ca.version'
             }),*/
            /* new Ext.form.DisplayField({
             fieldLabel: '签发者',
             id: 'tab.x509Ca.sign'
             }),*/

            new Ext.form.DisplayField({
                fieldLabel: '开始日期',
                id: 'tab.x509Ca.start'
            }),
            new Ext.form.DisplayField({
                fieldLabel: '截止日期',
                id: 'tab.x509Ca.end'
            }),new Ext.form.DisplayField({
                fieldLabel: '证书序列号',
                id: 'tab.x509Ca.serial'
            })
            /* {
             //                hideLabel:true,
             fieldLabel:'颁发机构信息',
             xtype: 'displayfield',
             //                value: '<a href="#" align="center" style="font-size:15;" onclick="show_info();"><b><font style="font-size: 15" color="#00008b">CA信息</font></b></a>',
             value: '<input type="button" value="颁发机构信息" onclick="show_info();"/>',
             plain: true,
             border: false,
             bodyStyle: 'background:none;'
             }, */ /*{
             //                hideLabel:true,
             xtype: 'displayfield',
             fieldLabel:'证书信息',
             plain: true,
             id: 'show_certificate',
             //                html: '<a href="#" align="center" style="font-size:15;" onclick="show_certificate();"><b><font color="#00008b">查看证书</font></b></a>'
             value: '<input type="button" value="证书信息" onclick="show_certificate();"/>'
             },*/
            /* {
             hideLabel:true,
             xtype: 'displayfield',
             plain: true,
             id: 'show_info',
             html: '<a href="#" align="center" style="font-size:15;" onclick="show_info();"><b><font color="blue">查看信息</font></b></a>'
             },*/
            /*{
             //                hideLabel:true,
             xtype: 'displayfield',
             fieldLabel:'PEM格式证书',
             plain: true,
             id: 'show_pem',
             //                html: '<a href="#" align="center" style="font-size:15;" onclick="show_pem();"><b><font color="#00008b">下载PEM格式证书</font></b></a>'
             value: '<input type="button" value="下载PEM格式证书" onclick="show_pem();"/>'

             }       ,*/

            /* {
             hideLabel:true,
             xtype: 'displayfield',
             plain: true,
             id: 'show_ie',
             html: '<a href="#" align="center" style="font-size:15;" onclick="show_ie();"><b><font color="#00008b">下载IE证书</font></b></a>'
             }  ,*/

            /* {
             hideLabel:true,
             xtype: 'displayfield',
             plain: true,
             id: 'show_bks',
             html: '<a href="#" align="center" style="font-size:15;" onclick="show_bks();"><b><font color="#00008b">下载BKS证书链</font></b></a>'
             } ,
             {
             hideLabel:true,
             xtype: 'displayfield',
             align:'center',
             plain: true,
             id: 'show_jks',
             html: '<a href="#" align="center" style="font-size:15;" onclick="show_jks();"><b><font color="#00008b">下载JKS证书链</font></b></a>'
             },*/
            /* {
             hideLabel:true,
             xtype: 'displayfield',
             align:'center',
             plain: true,
             id: 'show_crl',
             html: '<font>最新CRL:</font><input type="button" value="CRL信息" onclick="show_crl_msg();"/>'
             },*//*{
             //                hideLabel:true,
             xtype: 'displayfield',
             fieldLabel:'生成新的CRL',
             //                align:'center',
             plain: true,
             id: 'make_crl',
             html: '<input type="button" value="生成新的CRL" onclick="make_crl();"/>'
             },{
             //                hideLabel:true,
             xtype: 'displayfield',
             fieldLabel:'下载CRL',
             //                align:'center',
             plain: true,
             id: 'down_crl',
             //                html: '<font>下载CRL:</font><a href="#" align="center" style="font-size:15;" onclick="show_crl();"><b><font color="#00008b">下载CRL</font></b></a>'
             html: '<input type="button" value="下载CRL" onclick="show_crl();"/>'
             }*/
        ],
        buttons: [
            '->',
            /* {
             id:'button_certificate_info',
             text:'证书',
             handler:function () {
             show_certificate();
             }
             }, */{
                id: 'button_certificate_pem',
                text: '下载证书',
                handler: function () {
                    show_pem();
                }
            }, {
                id: 'button_certificate_create_crl',
                text: '生成黑名单',
                handler: function () {
                    make_crl();
                }
            }, {
                id: 'button_certificate_down_crl',
                text: '下载黑名单',
                handler: function () {
                    show_crl();
                }
            }
        ]
    });


    var panel = new Ext.Panel({
        plain: true,
        width: 800,
        border: false,
        items: [
            {
                id: 'panel.info',
                xtype: 'fieldset',
                title: '颁发机构信息',
                width: 600,
                items: [tab]
            }
        ]
    });
    new Ext.Viewport({
        layout: 'fit',
        renderTo: Ext.getBody(),
        autoScroll: true,
        items: [
            {
                frame: true,
                autoScroll: true,
                items: [panel]
            }
        ]
    });

});

function show_info() {
    var record = new Ext.data.Record.create([
        {name: 'cn', mapping: 'cn'},
        {name: 'pwd', mapping: 'pwd'} ,
        {name: 'dn', mapping: 'dn'},
        {name: 'orgCode', mapping: 'orgCode'},
        {name: 'serial', mapping: 'serial'},
        {name: 'keyLength', mapping: 'keyLength'},
        {name: 'province', mapping: 'province'},
        {name: 'city', mapping: 'city'},
        {name: 'certType', mapping: 'certType'},
        {name: 'validity', mapping: 'validity'},
        {name: 'createDate', mapping: 'createDate'},
        {name: 'endDate', mapping: 'endDate'},
        {name: 'organization', mapping: 'organization'},
        {name: 'institution', mapping: 'institution'},
        {name: 'issueCa', mapping: 'issueCa'},
        {name: 'desc', mapping: 'desc'},
        {name: 'certStatus', mapping: 'certStatus'}
    ]);


    var reader = new Ext.data.JsonReader({
        totalProperty: "totalCount",
        root: "root"
    }, record);

    var province_store = new Ext.data.Store({
        reader: new Ext.data.JsonReader({
            fields: ["id", "districtName"],
            totalProperty: 'totalCount',
            root: 'root'
        }),
        listeners: {
            load: function (store, records, options) {// 读取完数据后设定默认值
                var value = Ext.getCmp("view.x509Ca.province").getValue();
                Ext.getCmp("view.x509Ca.province").setValue(value);
            }
        }
    });

    /* var city_store = new Ext.data.Store({
     autoLoad:true,
     reader: new Ext.data.JsonReader({
     fields: ["id", "districtName"],
     totalProperty: 'totalCount',
     root: 'root'
     }) ,
     listeners:{
     load : function(store, records, options) {// 读取完数据后设定默认值
     var value =  Ext.getCmp("view.x509Ca.city").getValue();
     Ext.getCmp("view.x509Ca.city").setValue(value);
     }
     }
     });*/

    var keyBits = [
        ['1024', '1024'],
        ['2048', '2048'],
        ['4096', '4096']
    ];

    var formPanel = new Ext.form.FormPanel({
        frame: true,
        width: 500,
        autoScroll: true,
        baseCls: 'x-plain',
        labelAlign: 'right',
        defaultWidth: 300,
        layout: 'form',
        border: false,
        reader: reader,
        labelWidth: 100,
        defaultType: 'textfield',
        defaults: {
            width: 250,
            anchor: '95%',
            allowBlank: false,
            blankText: '该项不能为空!'
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '通用名',
                name: 'cn',
//                disabled:true,
                readOnly: true,
                emptyText: "请输入用户姓名",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                id: 'view.x509Ca.cn',
                allowBlank: false,
                blankText: "不能为空，请正确填写"/*,
                 listeners: {
                 blur: function () {
                 var thisCommon = Ext.getCmp("view.x509Ca.cn");
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
                 Ext.getCmp('view.x509Ca.cn').setValue('');
                 }
                 }
                 });
                 }
                 }
                 });
                 }
                 }*/
            }),
            new Ext.form.DisplayField({
                mode: 'remote',// 指定数据加载方式，如果直接从客户端加载则为local，如果从服务器断加载// 则为remote.默认值为：remote
                border: true,
                readOnly: true,
                frame: true,
                pageSize: 10,// 当元素加载的时候，如果返回的数据为多页，则会在下拉列表框下面显示一个分页工具栏，该属性指定每页的大小
                // 在点击分页导航按钮时，将会作为start及limit参数传递给服务端，默认值为0，只有在mode='remote'的时候才能够使用
                fieldLabel: '省/行政区',
                emptyText: '请选择所在省/行政区',
                id: 'view.x509Ca.province',
                name: 'province',
                disable: true,
//                hiddenName : 'province',
                triggerAction: "all",// 是否开启自动查询功能
                store: province_store,// 定义数据源
                displayField: "districtName", // 关联某一个逻辑列名作为显示值
                valueField: "districtName", // 关联某一个逻辑列名作为显示值
//                valueField: "id", // 关联某一个逻辑列名作为实际值
                //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
//                    name: 'x509User.province',
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
                }/*,
                 listeners: {
                 select: function () {
                 var value = this.getValue();
                 city_store.proxy = new Ext.data.HttpProxy({
                 url: "../../DistrictAction_findCity.action?parentId=" + value
                 })
                 city_store.load();
                 },
                 afterRender:function(){
                 var value = Ext.getCmp("view.x509Ca.province").getValue();
                 if(value != null){
                 city_store.proxy = new Ext.data.HttpProxy({
                 url: "../../DistrictAction_findCity.action?parentId=" + value
                 })
                 city_store.load();
                 }
                 }
                 }*/
            }),
            /*new Ext.form.DisplayField({
             mode: 'remote',// 指定数据加载方式，如果直接从客户端加载则为local，如果从服务器断加载// 则为remote.默认值为：remote
             border: true,
             frame: true,
             pageSize: 10,// 当元素加载的时候，如果返回的数据为多页，则会在下拉列表框下面显示一个分页工具栏，该属性指定每页的大小
             // 在点击分页导航按钮时，将会作为start及limit参数传递给服务端，默认值为0，只有在mode='remote'的时候才能够使用
             editable: false,
             fieldLabel: '城市/乡镇',
             emptyText: '请选择所在城市/乡镇',
             id: 'view.x509Ca.city',
             hiddenName: 'city',
             triggerAction: "all",// 是否开启自动查询功能
             store: city_store,// 定义数据源
             displayField: "districtName", // 关联某一个逻辑列名作为显示值
             valueField: "id", // 关联某一个逻辑列名作为实际值
             //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
             //                    name: 'x509User.city',
             allowBlank: false,
             blankText: "请选择所在城市/乡镇"
             }),*/
            new Ext.form.DisplayField({
                fieldLabel: '城市/乡镇',
                name: 'city',
                readOnly: true,
                emptyText: "请输入所在城市/乡镇",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                id: 'msg.x509Ca.city',
                allowBlank: false,
                blankText: "不能为空，请正确填写所在城市/乡镇"
            }),
            new Ext.form.DisplayField({
                fieldLabel: '密钥位数',
                emptyText: '请选择密钥位数',
                typeAhead: true,
                readOnly: true,
                triggerAction: 'all',
                forceSelection: true,
                id: "view.x509Ca.keyLength",
                mode: 'local',
//                hiddenName:"keyLength",
                name: 'keyLength',
                store: new Ext.data.ArrayStore({
                    fields: [
                        'id',
                        'name'
                    ],
                    data: keyBits
                }),
                valueField: 'id', //下拉框具体的值
                displayField: 'id'//下拉框显示内容
            }),
            {
                fieldLabel: '有效期(天)',
                allowBlank: false,
                xtype: 'displayfield',
                readOnly: true,
                value: 3650,
                name: 'validity',
                id: 'view.x509Ca.validity',
                listeners: {
                    render: function () {
                        Ext.getCmp('view.x509Ca.validity').setReadOnly(true);
                    }
                }
            }
        ],
        listeners: {
            render: function () {
                formPanel.getForm().load({
                    url: "../../X509CaAction_findSelf.action"
                });
            }
        }
    });

    var select_Win = new Ext.Window({
        title: "颁发机构信息",
        width: 500,
        layout: 'fit',
        height: 230,
        plain: true,
        bodyStyle: 'padding:5px;',
        buttonAlign: 'center',
        items: formPanel,
        bbar: [
            '->', {
                text: '关闭',
                handler: function () {
                    select_Win.close();
                }
            }]
    });
    select_Win.show();
}

function make_crl() {
    Ext.Msg.confirm("提示", "是否创建新的CRL文件？", function (sid) {
        if (sid == "yes") {
            Ext.Ajax.request({
                url: "../../CRL_createCRL.action",
                timeout: 20 * 60 * 1000,
                method: "POST",
                success: function (form, action) {
                    Ext.MessageBox.show({
                        title: '信息',
                        width: 250,
                        msg: '创建新的CRL成功!',
                        buttons: Ext.MessageBox.OK,
                        buttons: {'ok': '确定'},
                        icon: Ext.MessageBox.OK,
                        closable: false
                    });
                },
                failure: function (result) {
                    Ext.MessageBox.show({
                        title: '信息',
                        width: 250,
                        msg: '创建新的CRL失败!',
                        buttons: Ext.MessageBox.ERROR,
                        buttons: {'ok': '确定'},
                        icon: Ext.MessageBox.ERROR,
                        closable: false
                    });
                }
            });
        }
    });
}

function show_crl() {
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    }
    ;
    Ext.Ajax.request({
        url: '../../CRL_download.action',
        timeout: 20 * 60 * 1000,
        form: Ext.fly('test'),
        method: 'POST',
        isUpload: true
    });
}

function show_jks() {
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    }
    ;
    Ext.Ajax.request({
        url: '../../X509CaAction_downloadCaJks.action',
        timeout: 20 * 60 * 1000,
        form: Ext.fly('test'),
        method: 'POST',
        isUpload: true
    });
}

function show_bks() {
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    }
    ;
    Ext.Ajax.request({
        url: '../../X509CaAction_downloadCaBks.action',
        timeout: 20 * 60 * 1000,
        form: Ext.fly('test'),
        method: 'POST',
        isUpload: true
    });
}

function show_ie() {
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    }
    ;
    Ext.Ajax.request({
        url: '../../X509CaAction_downloadCaIE.action',
        timeout: 20 * 60 * 1000,
        form: Ext.fly('test'),
        method: 'POST',
        isUpload: true
    });
}

function show_pem() {
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    }
    ;
    Ext.Ajax.request({
        url: '../../X509CaAction_downloadCaPem.action',
        timeout: 20 * 60 * 1000,
        form: Ext.fly('test'),
        method: 'POST',
        isUpload: true
    });
}

function show_certificate() {
    var record = new Ext.data.Record.create([
        {name: 'subject', mapping: 'subject'},
        {name: 'version', mapping: 'version'} ,
        {name: 'issue', mapping: 'issue'},
        {name: 'serial', mapping: 'serial'},
        {name: 'before', mapping: 'before'},
        {name: 'after', mapping: 'after'}
    ]);

    var reader = new Ext.data.JsonReader({
        totalProperty: "totalCount",
        root: "root"
    }, record);

    var show_certificate_formPanel = new Ext.form.FormPanel({
        frame: true,
        width: 500,
        autoScroll: true,
        baseCls: 'x-plain',
        labelAlign: 'right',
        defaultWidth: 300,
        layout: 'form',
        border: false,
        reader: reader,
        labelWidth: 100,
        defaultType: 'textfield',
        defaults: {
            width: 250,
            anchor: '95%',
            allowBlank: false,
            blankText: '该项不能为空!'
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '主题',
                name: 'subject',
                readOnly: true,
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            }),
            new Ext.form.DisplayField({
                fieldLabel: '版本',
                name: 'version',
                readOnly: true,
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            }),
            new Ext.form.DisplayField({
                fieldLabel: '签发者',
                name: 'issue',
                readOnly: true,
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            }),
            new Ext.form.DisplayField({
                fieldLabel: '序列号',
                name: 'serial',
                readOnly: true,
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            }),
            new Ext.form.DisplayField({
                fieldLabel: '开始日期',
                name: 'before',
                readOnly: true,
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            }),
            new Ext.form.DisplayField({
                fieldLabel: '截止日期',
                name: 'after',
                readOnly: true,
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            })
        ],
        listeners: {
            render: function () {
                show_certificate_formPanel.getForm().load({
                    url: "../../X509CaAction_show_certificate.action"
                });
            }
        }
    });

    var Win = new Ext.Window({
        title: "证书信息",
        width: 500,
        layout: 'fit',
        height: 260,
        plain: true,
        bodyStyle: 'padding:5px;',
        buttonAlign: 'center',
        items: show_certificate_formPanel,
        bbar: [
            '->', {
                text: '关闭',
                handler: function () {
                    Win.close();
                }
            }]
    });
    Win.show();
}

function show_crl_msg() {
    alert("show_crl_msg");
}



