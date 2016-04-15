Ext.onReady(function () {
    Ext.BLANK_IMAGE_URL = '../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';

    var start = 0;
    var pageSize = 15;
    var record = new Ext.data.Record.create([
        {name: 'serverIp', mapping: 'serverIp'},
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
        url: "../../X509ServerAction_findServer.action",
        timeout: 20 * 60 * 1000
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

    store.load({
        params: {
            start: start, limit: pageSize
        }
    });

//    var boxM = new Ext.grid.CheckboxSelectionModel({singleSelect: true});   //复选框单选

    var rowNumber = new Ext.grid.RowNumberer();         //自动编号

    var colM = new Ext.grid.ColumnModel([
//        boxM,
        rowNumber,
        {header: "设备IP/域名", dataIndex: "cn", sortable: true, menuDisabled: true, sort: true} ,
        {header: "省/行政区", dataIndex: "province", sortable: true, menuDisabled: true} ,
        {header: "城市/乡镇", dataIndex: "city", sortable: true, menuDisabled: true} ,
        {header: "公司/团体", dataIndex: "organization", sortable: true, menuDisabled: true} ,
        {header: "部门/机构", dataIndex: "institution", sortable: true, menuDisabled: true} ,
//        {header:"状态", dataIndex:"certStatus", sortable:true, menuDisabled:true} ,
        {header: '操作标记', dataIndex: 'flag', sortable: true, menuDisabled: true, renderer: show_flag, width: 300}
    ]);

    var page_toolbar = new Ext.PagingToolbar({
        pageSize: pageSize,
        store: store,
        displayInfo: true,
        displayMsg: "显示第{0}条记录到第{1}条记录，一共{2}条",
        emptyMsg: "没有记录",
        beforePageText: "当前页",
        afterPageText: "共{0}页"
    });

    function setHeight() {
        var h = document.body.clientHeight - 8;
        return h;
    };

    var tb = new Ext.Toolbar({
        autoWidth: true,
        autoHeight: true,
        items: [
            {
                id: 'signServer.info',
                xtype: 'button',
                text: '签发设备证书',
                iconCls: 'add',
                handler: function () {
                    signServer(grid_panel, store);
                }
            },
            {
                id: 'signRequest.info',
                xtype: 'button',
                text: '签发设备请求',
                iconCls: 'add',
                handler: function () {
                    signRequest(grid_panel, store);
                }
            }
        ]
    });

    var tbar = new Ext.Toolbar({
        autoWidth: true,
        autoHeight: true,
        items: ['设备IP/域名',
            new Ext.form.TextField({
                id: 'tbar.cn',
                name: 'tbar.cn'
            }), {
                id: 'tbar.select.info',
                xtype: 'button',
                iconCls: 'select',
                text: '查询',
                handler: function () {
                    var cn = Ext.getCmp('tbar.cn').getValue();
                    store.setBaseParam('cn', cn.trim());
                    store.load({
                        params: {
                            start: start,
                            limit: pageSize
                        }
                    });
//                    Ext.getCmp('tbar.cn').reset();
                }
            } ]
    });

    var grid_panel = new Ext.grid.GridPanel({
        id: 'grid.info',
        plain: true,
        height: setHeight(),
        viewConfig: {
            //让grid的列自动填满grid的整个宽度，不用一列一列的设定宽度。
            forceFit: true
        },
        bodyStyle: 'width:100%',
        loadMask: {msg: '正在加载数据，请稍后...'},
        border: true,
        cm: colM,
//        sm: boxM,
        store: store,
        tbar: tb,
        listeners: {
            render: function () {
                tbar.render(this.tbar);
            }
        },
        bbar: page_toolbar
    });

    var port = new Ext.Viewport({
        layout: 'fit',
        renderTo: Ext.getBody(),
        items: [grid_panel]
    });
});

function show_flag(value, p, r) {
    if (r.get("certStatus") == "0") {
        return String.format(
            '<a id="downCertificate.info" href="javascript:void(0);" onclick="downCertificate();return false;"style="color: green;">下载</a> &nbsp;&nbsp;&nbsp;'+
            '<a id="revokeServer.info" href="javascript:void(0);" onclick="revokeServer();return false;"style="color: green;">吊销设备</a>&nbsp;&nbsp;&nbsp;' +
                '<a id="viewInfo.info" href="javascript:void(0);" onclick="viewInfo();return false;"style="color: green;">查看详细</a> &nbsp;&nbsp;&nbsp;'
        );
    } else {
        return String.format(
            '<a id="destroyServer.info" href="javascript:void(0);" onclick="destroyServer();return false;"style="color: green;">注销设备</a>&nbsp;&nbsp;&nbsp;' +
                '<a id="viewInfo.info" href="javascript:void(0);" onclick="viewInfo();return false;"style="color: green;">查看详细</a> &nbsp;&nbsp;&nbsp;');
    }
}

function signRequest(grid_panel, store) {
    var form = new Ext.form.FormPanel({
        baseCls: 'x-plain',
        labelWidth: 150,
        labelAlign: 'right',
        fileUpload: true,
        defaultType: 'textfield',
        defaults: {
             anchor: '95%'/*,
             allowBlank: false,
             blankText: '该项不能为空！'*/
        },
        items: [
            {
                id: 'uploadFile',
                allowBlank:false,
                name: 'uploadFile',
                fieldLabel: '请求文件',
                xtype: 'textfield',
                inputType: 'file',
                editable: false,
                listeners: {
                    blur: function () {
                        form.getForm().submit({
                            url: '../../X509ServerAction_parseRequest.action',
                            timeout: 20 * 60 * 1000,
                            method: "POST",
                            success: function (form, action) {
                                var flag = action.result.flag;
                                if(flag){
                                    Ext.getCmp("request_msg").setValue(action.result.msg);
                                    Ext.getCmp("request_cn").setValue(action.result.CN);
                                    Ext.getCmp("request_province").setValue(action.result.ST);
                                    Ext.getCmp("request_city").setValue(action.result.L);
                                    Ext.getCmp("request_organization").setValue(action.result.O);
                                    Ext.getCmp("request_institution").setValue(action.result.OU);
                                }else{
                                    Ext.getCmp("request_msg").setValue(action.result.msg);
                                    Ext.getCmp("request_sign.submit").setDisabled(true);
                                    Ext.getCmp("request_cn").setValue('');
                                    Ext.getCmp("request_province").setValue('');
                                    Ext.getCmp("request_city").setValue('');
                                    Ext.getCmp("request_organization").setValue('');
                                    Ext.getCmp("request_institution").setValue('');
                                }
                            }
                        });
                    }
                }
            },
            {
                id: 'request_msg',
                allowBlank:true,
                fieldLabel: '读取结果',
                xtype: 'textfield',
                readOnly:true
            }, {
                id: 'request_cn',
                allowBlank:true,
                name:'x509Server.cn',
                fieldLabel: '设备名称',
                xtype: 'textfield',
                readOnly:true
            },
            {
                id: 'request_province',
                allowBlank:true,
                name:'x509Server.province',
                fieldLabel: '省/行政区',
                xtype: 'textfield',
                readOnly:true
            }, {
                id: 'request_city',
                allowBlank:true,
                name:'x509Server.city',
                fieldLabel: '城市/乡镇',
                xtype: 'textfield',
                readOnly:true
            }, {
                id: 'request_organization',
                name:'x509Server.organization',
                allowBlank:true,
                fieldLabel: '公司/团体',
                xtype: 'textfield',
                readOnly:true
            },
            {
                id: 'request_institution',
                name:'x509Server.institution',
                allowBlank:true,
                fieldLabel: '部门/机构',
                xtype: 'textfield',
                readOnly:true
            }
        ]
    });

    var win = new Ext.Window({
        title: '签发设备请求',
        width: 500,
        height: 300,
        layout: 'fit',
        plain: true,
        bodyStyle: 'padding:5px;',
        buttonAlign: 'center',
        items: form,
        bbar: [
            '->', {
                text: '签发设备请求',
                id:'request.sign.submit',
                handler: function () {
                    if (form.getForm().isValid()) {
                        Ext.Msg.confirm("提示", "签发一个设备证书将耗费二个license名额,是否继续?", function (sid) {
                            if (sid == "yes") {
                                var cn = Ext.getCmp("request_cn").getValue();
                                if(cn!=''){
                                    Ext.Ajax.request({
                                        url: '../../X509ServerAction_existServer.action',
                                        method: 'post',
                                        timeout: 20 * 60 * 1000,
                                        params: {
                                            cn: cn
                                        },
                                        success: function (r, o) {
                                            var respText = Ext.util.JSON.decode(r.responseText);
                                            if (respText.flag == 'false') {
                                                Ext.Msg.confirm("提示", "设备名称已被使用,是否替换?", function (sid) {
                                                    if (sid == "yes") {
                                                        form.getForm().submit({
                                                            url: '../../X509ServerAction_signRequest.action',
                                                            timeout: 20 * 60 * 1000,
                                                            params:{command:"update"},
                                                            method: "POST",
                                                            waitTitle: '系统提示',
                                                            waitMsg: '正在签发...',
                                                            success: function (form, action) {
                                                                Ext.MessageBox.alert("提示",action.result.msg);
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
                                                });
                                            }else{
                                                form.getForm().submit({
                                                    url: '../../X509ServerAction_signRequest.action',
                                                    timeout: 20 * 60 * 1000,
                                                    method: "POST",
                                                    params:{command:"add"},
                                                    waitTitle: '系统提示',
                                                    waitMsg: '正在签发...',
                                                    success: function (form, action) {
                                                        Ext.MessageBox.alert("提示",action.result.msg);
                                                        store.reload();
                                                        win.close();
                                                    } ,
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
                                    });
                                }
                            }
                        })
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
};

function viewInfo() {
    var grid_panel = Ext.getCmp("grid.info");
    var recode = grid_panel.getSelectionModel().getSelected();
    var status = recode.get("certStatus")
    var statusValue;
    if (status == "0") {
        statusValue = "<font color='green'>已发证</font>"
    } else if (status == "1") {
        statusValue = "<font color='red'>已吊销</font>"
    }
    var formPanel = new Ext.form.FormPanel({
        frame: true,
        autoScroll: true,
        baseCls: 'x-plain',
        labelWidth: 150,
        labelAlign: 'right',
        defaultWidth: 280,
        width: 500,
        layout: 'form',
        border: false,
        defaults: {
            width: 250
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '设备IP/域名',
                value: recode.get("cn")
            }),
            /*  new Ext.form.DisplayField({
             fieldLabel:'DN',
             value:recode.get("dn")
             }),*/
          /*  new Ext.form.DisplayField({
                fieldLabel: '设备IP',
                value: recode.get("serverIp")
            }),*/
            new Ext.form.DisplayField({
                fieldLabel: '频发者',
                value: recode.get("issueCa")
            }) ,
            new Ext.form.DisplayField({
                fieldLabel: '省/行政区',
                value: recode.get("province")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '城市/乡镇',
                value: recode.get("city")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '公司/团体',
                value: recode.get("organization")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '部门/机构',
                value: recode.get("institution")
            })  ,
            new Ext.form.DisplayField({
                fieldLabel: '状态',
                value: statusValue
            })
        ]
    });

    var select_Win = new Ext.Window({
        title: "设备详细",
        width: 500,
        layout: 'fit',
        height: 250,
        modal: true,
        items: formPanel
    });
    select_Win.show();
}

function signServer(grid_panel, store) {
    var province_store = new Ext.data.Store({
        reader: new Ext.data.JsonReader({
            fields: ["id", "districtName"],
            totalProperty: 'totalCount',
            root: 'root'
        })
    });

   /* var city_store = new Ext.data.Store({
        reader: new Ext.data.JsonReader({
            fields: ["id", "districtName"],
            totalProperty: 'totalCount',
            root: 'root'
        })
    });*/

    var formPanel = new Ext.form.FormPanel({
        frame: true,
        autoScroll: true,
        labelWidth: 100,
        labelAlign: 'right',
        defaultWidth: 300,
        autoWidth: true,
        layout: 'form',
        border: false,
        defaults: {
            anchor: '95%',
            allowBlank: false,
            blankText: '该项不能为空！'
        },
        items: [
            new Ext.form.TextField({
                fieldLabel: '设备IP/域名',
                name: 'x509Server.cn',
                id: 'signServer.x509Server.cn',
                allowBlank: false,
//                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
//                regexText: '只能输入数字,字母,中文!',
                regex: /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){3}$/,
                regexText: '请输入正确的IP地址',
                blankText: "不能为空，请正确填写",
                listeners: {
                    blur: function () {
                        var thisText = Ext.getCmp("signServer.x509Server.cn").getValue();
                        if (thisText != '') {
                            Ext.Ajax.request({
                                url: '../../X509ServerAction_existServer.action',
                                method: 'post',
                                timeout: 20 * 60 * 1000,
                                params: {
                                    cn: thisText
                                },
                                success: function (r, o) {
                                    var respText = Ext.util.JSON.decode(r.responseText);
                                    if (respText.msg == 'false') {
                                        Ext.MessageBox.show({
                                            title: '信息',
                                            width: 250,
                                            msg: '设备名称已被使用,请更换！',
                                            buttons: Ext.MessageBox.OK,
                                            buttons: {'ok': '确定'},
                                            icon: Ext.MessageBox.INFO,
                                            closable: false,
                                            fn: function (e) {
                                                if (e == 'ok') {
                                                    Ext.getCmp('signServer.x509Server.cn').setValue('');
                                                }
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    }
                }
            }),
           /* new Ext.form.TextField({
                fieldLabel: '设备描述',
                name: 'x509Server.serverIp',
                id: 'x509Server.signServer.serverIp',
                regex: /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){3}$/,
                regexText: '请输入正确的IP地址',
                allowBlank: false,
                blankText: "不能为空，请正确填写"
            }),*/
            new Ext.form.ComboBox({
                mode: 'remote',// 指定数据加载方式，如果直接从客户端加载则为local，如果从服务器断加载// 则为remote.默认值为：remote
                border: true,
                frame: true,
                pageSize: 10,// 当元素加载的时候，如果返回的数据为多页，则会在下拉列表框下面显示一个分页工具栏，该属性指定每页的大小
                // 在点击分页导航按钮时，将会作为start及limit参数传递给服务端，默认值为0，只有在mode='remote'的时候才能够使用
                editable: false,
                fieldLabel: '省/行政区',
                emptyText: '请选择所在省/行政区',
                id: 'signServer.x509Server.province',
//                hiddenName : 'x509Server.province',
                triggerAction: "all",// 是否开启自动查询功能
                store: province_store,// 定义数据源
                displayField: "districtName", // 关联某一个逻辑列名作为显示值
                valueField: "districtName", // 关联某一个逻辑列名作为显示值
//                valueField: "id", // 关联某一个逻辑列名作为实际值
                //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                name: 'x509Server.province',
                allowBlank: false,
                blankText: "请选择所在省/行政区",
                listeners: {
                    /*select: function () {
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
                id: 'x509Server.signServer.city',
//                hiddenName: 'x509Server.orgCode',
                triggerAction: "all",// 是否开启自动查询功能
                store: city_store,// 定义数据源
                displayField: "districtName", // 关联某一个逻辑列名作为显示值
                valueField: "id", // 关联某一个逻辑列名作为实际值
                //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                name: 'x509Server.city',
                allowBlank: false,
                blankText: "请选择所在城市/乡镇"
            }),*/
            new Ext.form.TextField({
                fieldLabel: '城市/乡镇',
                name: 'x509Server.city',
                emptyText:"请输入所在城市/乡镇",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                allowBlank: false,
                blankText: "不能为空，请正确填写所在城市/乡镇"
            }),
            new Ext.form.TextField({
                fieldLabel: '公司/团体',
                allowBlank: false,
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                blankText: "不能为空，请正确填写",
                name: 'x509Server.organization'
            }),
            new Ext.form.TextField({
                fieldLabel: '部门/机构',
                allowBlank: false,
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                blankText: "不能为空，请正确填写",
                name: 'x509Server.institution'
            })/*,
            new Ext.form.TextField({
                fieldLabel: '描述',
                allowBlank: false,
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                blankText: "不能为空，请正确填写",
                name: 'x509Server.desc'
            })*/
        ]
    });
    var win = new Ext.Window({
        title: "签发设备",
        width: 500,
        layout: 'fit',
        height: 280,
        modal: true,
        items: formPanel,
        bbar: [
            '->',
            {
                id: 'insert_win.info',
                text: '签发设备',
                handler: function () {
                    if (formPanel.form.isValid()) {
                        Ext.Msg.confirm("提示", "签发一个设备证书将耗费二个license名额,是否继续?", function (sid) {
                            if (sid == "yes") {
                                formPanel.getForm().submit({
                                    url: "../../X509ServerAction_signServer.action",
                                    method: 'POST',
                                    timeout: 20 * 60 * 1000,
                                    waitTitle: '系统提示',
                                    waitMsg: '正在连接...',
                                    success: function (form, action) {
                                        var json = Ext.decode(action.response.responseText);
                                        var msg = json.msg;
                                        Ext.MessageBox.show({
                                            title: '信息',
                                            width: 250,
                                            msg: msg,
                                            buttons: Ext.MessageBox.OK,
                                            buttons: {'ok': '确定'},
                                            icon: Ext.MessageBox.INFO,
                                            closable: false,
                                            fn: function (e) {
                                                grid_panel.render();
                                                store.reload();
                                                win.close();
                                            }
                                        });
                                    },
                                    failure: function (form, action) {
                                        var json = Ext.decode(action.response.responseText);
                                        var msg = json.msg;
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
                        })
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
            }, {
                text: '重置',
                handler: function () {
                    formPanel.getForm().reset();
                }
            }
        ]
    }).show();
};

function destroyServer() {
    var grid_panel = Ext.getCmp("grid.info");
    var recode = grid_panel.getSelectionModel().getSelected();
    if (!recode) {
        Ext.Msg.alert("提示", "请选择一条记录!");
    } else {
        Ext.Msg.confirm("提示", "确认删除吗？", function (sid) {
            var re = recode.get("dn");
            if (sid == "yes") {
                Ext.Ajax.request({
                    url: "../../X509ServerAction_delServer.action",
                    method: "POST",
                    timeout: 20 * 60 * 1000,
                    params: {
                        DN: re
                    },
                    success: function (form, action) {
                        grid_panel.getStore().reload();
                        Ext.Msg.alert("提示", "删除成功!");
                    },
                    failure: function (result) {
                        Ext.Msg.alert("提示", "删除失败!");
                    }
                });
            }
        });
    }
};

function revokeServer() {
    var grid = Ext.getCmp('grid.info');
    var recode = grid.getSelectionModel().getSelected();
    var CN = recode.get("cn");
    var DN = recode.get("dn");
    Ext.Msg.confirm("警告", "确认吊销证书,吊销后证书不可用!", function (sid) {
        if (sid == "yes") {
            Ext.Ajax.request({
                url: '../../X509ServerAction_revokeServer.action',
                timeout: 20 * 60 * 1000,
                params: {DN: DN, CN: CN},
                method: 'POST',
                success: function (form, action) {
                    Ext.Msg.alert("提示", "吊销证书成功!");
                    grid.getStore().reload();
                },
                failure: function (result) {
                    Ext.Msg.alert("提示", "吊销证书失败!");
                    grid.getStore().reload();
                }
            });
        }
    });
}

function downCertificate(){
    var grid = Ext.getCmp('grid.info');
    var recode = grid.getSelectionModel().getSelected();
    var CN = recode.get("cn");
    var DN = recode.get("dn");
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    } ;
    Ext.Ajax.request({
        url: '../../X509ServerAction_downCertificate.action',
        timeout: 20*60*1000,
        form: Ext.fly('test'),
        params:{CN:CN,DN:DN},
        method: 'POST',
        isUpload: true
    });
}




