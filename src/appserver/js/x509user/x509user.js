Ext.onReady(function () {
    Ext.BLANK_IMAGE_URL = '../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';

    var start = 0;
    var pageSize = 15;
    var record = new Ext.data.Record.create([
        {name: 'cn', mapping: 'cn'},
        {name: 'pwd', mapping: 'pwd'},
        {name: 'dn', mapping: 'dn'},
        {name: 'orgCode', mapping: 'orgCode'},
        {name: 'province', mapping: 'province'},
        {name: 'city', mapping: 'city'},
        {name: 'organization', mapping: 'organization'},
        {name: 'institution', mapping: 'institution'},
        {name: 'idCard', mapping: 'idCard'},
        {name: 'phone', mapping: 'phone'},
        {name: 'address', mapping: 'address'},
        {name: 'certType', mapping: 'certType'},
        {name: 'userEmail', mapping: 'userEmail'},
        {name: 'employeeCode', mapping: 'employeeCode'},
        {name: 'issueCa', mapping: 'issueCa'},
        {name: 'validity', mapping: 'validity'},
        {name: 'createDate', mapping: 'createDate'},
        {name: 'endDate', mapping: 'endDate'},
        {name: 'serial', mapping: 'serial'},
        {name: 'keyLength', mapping: 'keyLength'},
        {name: 'desc', mapping: 'desc'},
        {name: 'certStatus', mapping: 'certStatus'}

    ]);

    var proxy = new Ext.data.HttpProxy({
        url: "../../X509UserAction_findUser.action",
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
        {header: "姓名", dataIndex: "cn", sortable: true, menuDisabled: true, sort: true},
        {header: "身份证", dataIndex: "idCard", sortable: true, menuDisabled: true},
        {header: "联系电话", dataIndex: "phone", sortable: true, menuDisabled: true},
        {header: "联系地址", dataIndex: "address", sortable: true, menuDisabled: true},
        {header: "电子邮件", dataIndex: "userEmail", sortable: true, hidden: true, menuDisabled: true},
        {header: "省/行政区", dataIndex: "orgCode", sortable: true, menuDisabled: true, hidden: true},
        {header: "城市/乡镇", dataIndex: "city", sortable: true, menuDisabled: true, hidden: true},
        {header: "公司/团体", dataIndex: "organization", sortable: true, menuDisabled: true},
        {header: "部门/机构", dataIndex: "institution", sortable: true, menuDisabled: true},
        {header: "警员编号", dataIndex: "employeeCode", sortable: true, menuDisabled: true},
        {header: "状态", dataIndex: "certStatus", hidden: true, sortable: true, menuDisabled: true},
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
                id: 'signUser.info',
                xtype: 'button',
                text: '签发证书',
                iconCls: 'add',
                handler: function () {
                    signUser(store);
                }
            },
            {
                id: 'batchSignUser.info',
                xtype: 'button',
                text: '批量签发证书',
                iconCls: 'replace',
                handler: function () {
                    batchSignUser(store);
                }
            },
            {
                id: 'batchExportUser.info',
                xtype: 'button',
                text: '导出为Excel',
                iconCls: 'replace',
                handler: function () {
                    batchExportUser();
                }
            }
        ]
    });

    var tbar = new Ext.Toolbar({
        autoWidth: true,
        autoHeight: true,
        items: [
            '姓名',
            new Ext.form.TextField({
                name: 'username',
                id: 'tbar.select.cn'
            }),
            '身份证号码',
            new Ext.form.TextField({
                id: 'tbar.select.idCard',
                regex: /^(\d{6})()?(\d{4})(\d{2})(\d{2})(\d{3})([0-9xX])$/,
                regexText: '请输入有效的身份证号'
            }),
            {
                id: 'tbar.select.info',
                xtype: 'button',
                iconCls: 'select',
                text: '查询',
                handler: function () {
                    var cn = Ext.getCmp('tbar.select.cn').getValue();
                    var idCard = Ext.getCmp('tbar.select.idCard').getValue();
                    store.setBaseParam('cn', cn.trim());
                    store.setBaseParam('idCard', idCard.trim());
                    store.load({
                        params: {
                            start: start,
                            limit: pageSize
                        }
                    });
//                    Ext.getCmp('tbar.model.cn').reset();
//                    Ext.getCmp('tbar.select.idCard').reset();
                }
            }]
    });

    var grid_panel = new Ext.grid.GridPanel({
        id: 'grid.info',
        plain: true,
        height: setHeight(),
        viewConfig: {
            forceFit: true //让grid的列自动填满grid的整个宽度，不用一列一列的设定宽度。
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
            '<a id="modifyUser.info" href="javascript:void(0);" onclick="modifyUser();return false;"style="color: green;">更新证书</a>&nbsp;&nbsp;&nbsp;' +
            '<a id="restoreUser.info" href="javascript:void(0);" onclick="restoreUser();return false;"style="color: green;">恢复证书</a>&nbsp;&nbsp;&nbsp;' +
            '<a id="revokeUser.info" href="javascript:void(0);" onclick="revokeUser();return false;"style="color: green;">吊销证书</a>&nbsp;&nbsp;&nbsp;' +
            '<a id="retryUser.info" href="javascript:void(0);" onclick="retryUser();return false;"style="color: green;">重发证书</a>&nbsp;&nbsp;&nbsp;' +
            '<a id="viewInfo.info" href="javascript:void(0);" onclick="viewInfo();return false;"style="color: green;">查看详细</a> &nbsp;&nbsp;&nbsp;'
        );
    } else {
        return String.format(
            '<a id="destroyUser.info" href="javascript:void(0);" onclick="destroyUser();return false;"style="color: green;">注销用户</a>&nbsp;&nbsp;&nbsp;' +
            '<a id="retryUser.info" href="javascript:void(0);" onclick="retryUser();return false;"style="color: green;">重发</a>&nbsp;&nbsp;&nbsp;' +
            '<a id="viewInfo.info" href="javascript:void(0);" onclick="viewInfo();return false;"style="color: green;">查看详细</a> &nbsp;&nbsp;&nbsp;'
        );
    }
};


/**
 * 查看用户详细
 */
function viewInfo() {
    var grid_panel = Ext.getCmp("grid.info");
    var recode = grid_panel.getSelectionModel().getSelected();
    var status = recode.get("certStatus")
    var status_v;
    if (status == "0") {
        var certType = recode.get("certType")
        status_v = "<font color='green'>已发"+certType+"证</font>";
    } else if (status == "1") {
        status_v = "<font color='red'>已吊销</font>";
    }
    var formPanel = new Ext.form.FormPanel({
        frame: true,
        width: 800,
        autoScroll: true,
        baseCls: 'x-plain',
        labelWidth: 150,
        labelAlign: 'right',
        defaultWidth: 300,
        layout: 'form',
        border: false,
        defaults: {
            width: 250
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '姓名',
                value: recode.get("cn")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '签发者',
                value: recode.get("issueCa")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '主题',
                value: recode.get("dn")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '身份证',
                value: recode.get("idCard")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '联系电话',
                value: recode.get("phone")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '联系地址',
                value: recode.get("address")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '电子邮件',
                value: recode.get("userEmail")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '警员编号',
                value: recode.get("employeeCode")
            }),
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
            }),
            new Ext.form.DisplayField({
                fieldLabel: '状态',
                value: status_v
            })
        ]
    });

    var select_Win = new Ext.Window({
        title: "详细信息",
        width: 650,
        layout: 'fit',
        height: 400,
        modal: true,
        items: formPanel
    });
    select_Win.show();
};

/**
 * 签发用户证书
 * @param grid_panel
 * @param store
 */
function signUser(store) {

    var ZdActivex = document.getElementById("ZdActivex");

    var cspProvider = ZdActivex.EnumCspProvider();

//    alert(cspProvider);

    //testJson=eval(testJson);//错误的转换方式
    var Json = eval("(" + cspProvider + ")");

    var cspProvider_store = new Ext.data.JsonStore({
        data: Json,
        totalProperty: "total",
        root: "rows",
        fields: ['value']
    });

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

    var smart_card = [
        ['TFCard', 'TFCard'],
        ['USBKey', "USBKey"]
    ];
    var smart_card_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: smart_card
    });


    var key_type_data = [
        ['签名密钥', "签名密钥"],
        ['交换密钥', '交换密钥']
    ];
    var key_type_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: key_type_data
    });

    var formPanel = new Ext.form.FormPanel({
        frame: true,
        autoScroll: true,
        labelWidth: 100,
        labelAlign: 'right',
        defaultWidth: 450,
        autoWidth: true,
        layout: 'form',
        border: false,
        defaults: {
            width: 450,
            allowBlank: false,
            anchor: '95%',
            blankText: '该项不能为空！'
        },
        items: [
            new Ext.form.TextField({
                fieldLabel: '姓名',
                name: 'x509User.cn',
                emptyText: "请输入用户姓名",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                id: 'add_x509User_cn',
                allowBlank: false,
                blankText: "不能为空，请正确填写",
                listeners: {
                    blur: function () {
                        var thisCommon = Ext.getCmp("add_x509User_cn");
                        var cn = thisCommon.getValue();
                        Ext.Ajax.request({
                            url: '../../X509UserAction_existUser.action',
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
                                        msg: '姓名称已被使用,请更换！',
                                        buttons: Ext.MessageBox.OK,
                                        buttons: {'ok': '确定'},
                                        icon: Ext.MessageBox.INFO,
                                        closable: false,
                                        fn: function (e) {
                                            if (e == 'ok') {
                                                Ext.getCmp('add_x509User_cn').setValue('');
                                            }
                                        }
                                    });
                                }
                            }
                        });
                    }
                }
            }),
            new Ext.form.TextField({
                fieldLabel: '身份证号码',
                emptyText: "请输入有效的身份证号",
                id: 'add_x509User_idCard',
                regex: /^(\d{6})()?(\d{4})(\d{2})(\d{2})(\d{3})([0-9xX])$/,
                regexText: '请输入有效的身份证号',
                allowBlank: false,
                blankText: "请填写数字 ，不能为空，请正确填写",
                name: 'x509User.idCard'
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
                id: 'add_x509User_province',
//                hiddenName : 'x509User.province',
                triggerAction: "all",// 是否开启自动查询功能
                store: province_store,// 定义数据源
                displayField: "districtName", // 关联某一个逻辑列名作为显示值
                valueField: "districtName", // 关联某一个逻辑列名作为显示值
//                valueField: "id", // 关联某一个逻辑列名作为实际值
                //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                name: 'x509User.province',
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
             id: 'signUser_x509User_city',
             //                hiddenName: 'x509User.orgCode',
             triggerAction: "all",// 是否开启自动查询功能
             store: city_store,// 定义数据源
             displayField: "districtName", // 关联某一个逻辑列名作为显示值
             valueField: "id", // 关联某一个逻辑列名作为实际值
             //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
             name: 'x509User.city',
             //                hiddenName: 'x509User.city',
             allowBlank: false,
             blankText: "请选择所在城市/乡镇"
             }),*/
            new Ext.form.TextField({
                fieldLabel: '城市/乡镇',
                name: 'x509User.city',
                emptyText: "请输入所在城市/乡镇",
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                id: 'add_x509User_city',
                allowBlank: false,
                blankText: "不能为空，请正确填写所在城市/乡镇"
            }),
            new Ext.form.TextField({
                fieldLabel: '公司/团体',
                emptyText: "请输入所在公司/团体",
                allowBlank: false,
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                blankText: "不能为空，请正确填写",
                name: 'x509User.organization'
            }),
            new Ext.form.TextField({
                fieldLabel: '部门/机构',
                emptyText: "请输入所在部门/机构",
                allowBlank: false,
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                blankText: "不能为空，请正确填写",
                name: 'x509User.institution'
            }),
            new Ext.form.TextField({
                emptyText: "请输入联系电话",
                fieldLabel: '联系电话',
                name: 'x509User.phone',
                regex: /^(1[3,4,5,8,7]{1}[\d]{9})|(((400)-(\d{3})-(\d{4}))|^((\d{7,8})|(\d{4}|\d{3})-(\d{7,8})|(\d{4}|\d{3})-(\d{3,7,8})-(\d{4}|\d{3}|\d{2}|\d{1})|(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1}))$)$/,
                //regex:/^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$|(^(13[0-9]|15[0|3|6|7|8|9]|18[8|9])d{8}$)/,
                //regex:/^((\d{11})|^((\d{7,8})|(\d{4}|\d{3})-(\d{7,8})|(\d{4}|\d{3})-(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1})|(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1}))$)$/,
                regexText: '请输入正确的电话号或手机号',
                allowBlank: false,
                blankText: "联系电话"
            }),
            new Ext.form.TextField({
                emptyText: "请输入联系地址",
                fieldLabel: '联系地址',
                regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                regexText: '只能输入数字,字母,中文!',
                name: 'x509User.address',
                allowBlank: false,
                blankText: "联系地址"
            }),
            new Ext.form.TextField({
                fieldLabel: '电子邮件',
                emptyText: "请输入电子邮件",
                regex: /^[0-9a-zA-Z_\-\.]+@[0-9a-zA-Z_\-]+(\.[0-9a-zA-Z_\-]+)*$/,
                regexText: '请输入有效的邮件地址',
                name: 'x509User.userEmail',
                allowBlank: false,
                blankText: "电子邮件"
            }),
            new Ext.form.TextField({
                fieldLabel: '警员编号',
                emptyText: "请输入警员编号",
                name: 'x509User.employeeCode',
                allowBlank: false,
                blankText: "警员编号"
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP设备类型',
                emptyText: '请选择写入证书设备类型',
                typeAhead: true,
                editable: false,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: 'add_x509User_smartCard_type',
                store: smart_card_store,
                valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'name',
                allowBlank: false,
                blankText: "请选择写入证书设备类型",
                listeners: {
                    afterRender: function () {
                        this.setValue(smart_card_store.getAt(0).data.id);
                    }
                }
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP密钥类型',
                emptyText: '请选择写入证书密钥类型',
                typeAhead: true,
                editable: false,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: 'add_x509User_key_type',
                store: key_type_store,
                valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'name',
                allowBlank: false,
                blankText: "请选择写入证书密钥类型",
                listeners: {
                    afterRender: function () {
                        this.setValue(key_type_store.getAt(1).data.id);
                    }
                }
            }),
            new Ext.form.TextField({
                fieldLabel: 'CSP容器名称',
                emptyText: '请输入导入硬件容器名称',
                allowBlank: false,
                value:"KingTrustVPN",
                id: 'add_x509User_smartCard_container',
                blankText: "请输入导入硬件容器名称"
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP加密设备',
                emptyText: 'CSP加密设备',
                typeAhead: true,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: "add_x509User_smartCard_csp",
                editable: false,
                store: cspProvider_store,
                valueField: 'value',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'value',//下拉框显示内容
                allowBlank: false,
                blankText: "请选择CSP加密设备"
            })

        ]
    });
    var win = new Ext.Window({
        title: "证书签发",
        width: 650,
        layout: 'fit',
        height: 450,
        modal: true,
        items: formPanel,
        bbar: [
            '->',
            {
                id: 'insert_win.info',
                text: '证书签发',
                handler: function () {
                    if (formPanel.form.isValid()) {
                        Ext.Msg.confirm("提示", "签发一个用户证书将耗费一个license名额,是否继续?", function (sid) {
                            if (sid == "yes") {
                                formPanel.getForm().submit({
                                    url: '../../X509UserAction_signX509User.action',
                                    timeout: 20 * 60 * 1000,
                                    method: 'POST',
                                    waitTitle: '系统提示',
                                    waitMsg: '正在连接...',
                                    success: function () {
                                        var cn = Ext.getCmp("add_x509User_cn").getValue();
                                        var csp = Ext.getCmp("add_x509User_smartCard_csp").getValue();
                                        var type = Ext.getCmp("add_x509User_smartCard_type").getRawValue();
                                        var container = Ext.getCmp("add_x509User_smartCard_container").getValue();
                                        var key_type = Ext.getCmp("add_x509User_key_type").getRawValue();
                                        Ext.Ajax.request({
                                            url: "../../X509UserAction_modifyUserSmartCard.action",
                                            waitTitle: '请等待',
                                            waitMsg: '正在提交',
                                            params: {CN: cn, type: type},
                                            success: function (res, p) {
                                                var json = Ext.util.JSON.decode(res.responseText);
                                                var dn = json.dn;
                                                getDownUrl(dn, cn, csp, type, container, ZdActivex, key_type);
                                                store.reload();
                                                win.close();
                                            },
                                            failure: function (result) {
                                                Ext.Msg.alert("提示", "删除失败!");
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

/**
 * 删除用户
 */
function destroyUser() {
    var grid_panel = Ext.getCmp("grid.info");
    var recode = grid_panel.getSelectionModel().getSelected();
    if (!recode) {
        Ext.Msg.alert("提示", "请选择一条记录!");
    } else {
        Ext.Msg.confirm("提示", "确认注销用户吗？", function (sid) {
            if (sid == "yes") {
                Ext.Ajax.request({
                    url: "../../X509UserAction_delUser.action",
                    timeout: 20 * 60 * 1000,
                    method: "POST",
                    params: {DN: recode.get("dn")},
                    success: function (form, action) {
                        grid_panel.getStore().reload();
                        Ext.Msg.alert("提示", "注销用户成功!");
                    },
                    failure: function (result) {
                        Ext.Msg.alert("提示", "注销用户失败!");
                    }
                });
            }
        });
    }
};

/**
 * 更新用户证书
 */
function modifyUser() {

    var ZdActivex = document.getElementById("ZdActivex");


    var cspProvider = ZdActivex.EnumCspProvider();

    //alert(cspProvider);

    //testJson=eval(testJson);//错误的转换方式
    var Json = eval("(" + cspProvider + ")");

    var cspProvider_store = new Ext.data.JsonStore({
        data: Json,
        totalProperty: "total",
        root: "rows",
        fields: ['value']
    });

    var proxy = new Ext.data.HttpProxy({
        url: '../../DistrictAction_findProvince.action',
        method: "POST",
        timeout: 20 * 60 * 1000
    });

    var province_store = new Ext.data.Store({
        proxy: proxy,
        reader: new Ext.data.JsonReader({
            fields: ["id", "districtName"],
            totalProperty: 'totalCount',
            root: 'root'
        }),
        listeners: {
            load: function (store, records, options) {// 读取完数据后设定默认值
                var value = Ext.getCmp("modifyUser.x509User.province").getValue();
                Ext.getCmp("modifyUser.x509User.province").setValue(value);
            }
        }
    });

//    province_store.load();

    /* var city_store = new Ext.data.Store({
     reader: new Ext.data.JsonReader({
     fields: ["id", "districtName"],
     totalProperty: 'totalCount',
     root: 'root'
     }) ,
     listeners:{
     load : function(store, records, options) {// 读取完数据后设定默认值
     var value =  Ext.getCmp("modifyUser.x509User.city").getValue();
     Ext.getCmp("modifyUser.x509User.city").setValue(value);
     }
     }
     });*/


    var smart_card = [
        ['TFCard', 'TFCard'],
        ['USBKey', "USBKey"]
    ];
    var smart_card_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: smart_card
    });

    var key_type_data = [
        ['签名密钥', "签名密钥"],
        ['交换密钥', '交换密钥']
    ];
    var key_type_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: key_type_data
    });


    var grid_panel = Ext.getCmp("grid.info");
    var record = grid_panel.getSelectionModel().getSelected();

    if (!record) {
        Ext.Msg.alert("提示", "请选择一条记录!");
    } else {
        var formPanel = new Ext.form.FormPanel({
            frame: true,
            autoScroll: true,
            labelWidth: 100,
            labelAlign: 'right',
            defaultWidth: 450,
            autoWidth: true,
            layout: 'form',
            border: false,
            defaults: {
                width: 450,
                anchor: '95%',
                allowBlank: false,
                blankText: '该项不能为空！'
            },
            items: [

                new Ext.form.TextField({
                    fieldLabel: '姓名',
                    name: 'x509User.cn',
                    readOnly: true,
                    regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                    regexText: '只能输入数字,字母,中文!',
                    id: 'modifyUser.x509User.cn',
                    value: record.get("cn"),
                    allowBlank: false,
                    blankText: "不能为空，请正确填写"
                }),
                new Ext.form.TextField({
                    fieldLabel: '身份证号码',
                    id: 'modifyUser.x509User.idCard',
                    value: record.get("idCard"),
                    regex: /^(\d{6})()?(\d{4})(\d{2})(\d{2})(\d{3})([0-9xX])$/,
                    regexText: '请输入有效的身份证号',
                    allowBlank: false,
                    blankText: "请填写数字 ，不能为空，请正确填写",
                    name: 'x509User.idCard'
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
                    id: 'modifyUser.x509User.province',
//                    hiddenName : 'x509User.province',
                    value: record.get("province"),
                    triggerAction: "all",// 是否开启自动查询功能
                    store: province_store,// 定义数据源
                    displayField: "districtName", // 关联某一个逻辑列名作为显示值
                    valueField: "districtName", // 关联某一个逻辑列名作为显示值
//                    valueField: "id", // 关联某一个逻辑列名作为实际值
                    //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                    name: 'x509User.province',
                    allowBlank: false,
                    blankText: "请选择所在省/行政区"/*,
                     listeners: {
                     select: function () {
                     var value = this.getValue();
                     city_store.proxy = new Ext.data.HttpProxy({
                     url: "../../DistrictAction_findCity.action?parentId=" + value
                     })
                     city_store.load();
                     },
                     afterRender:function(){
                     var value = this.getValue();
                     if(value!=null){
                     city_store.proxy = new Ext.data.HttpProxy({
                     url: "../../DistrictAction_findCity.action?parentId=" + value
                     })
                     city_store.load();
                     }
                     }
                     }*/
                }),
                /*new Ext.form.ComboBox({
                 mode: 'remote',// 指定数据加载方式，如果直接从客户端加载则为local，如果从服务器断加载// 则为remote.默认值为：remote
                 border: true,
                 frame: true,
                 pageSize: 10,// 当元素加载的时候，如果返回的数据为多页，则会在下拉列表框下面显示一个分页工具栏，该属性指定每页的大小
                 // 在点击分页导航按钮时，将会作为start及limit参数传递给服务端，默认值为0，只有在mode='remote'的时候才能够使用
                 editable: false,
                 fieldLabel: '城市/乡镇',
                 value:record.get('city'),
                 emptyText: '请选择所在城市/乡镇',
                 id: 'modifyUser.x509User.city',
                 //                    hiddenName: 'x509User.city',
                 triggerAction: "all",// 是否开启自动查询功能
                 store: city_store,// 定义数据源
                 displayField: "districtName", // 关联某一个逻辑列名作为显示值
                 valueField: "id", // 关联某一个逻辑列名作为实际值
                 //mode : "local",// 如果数据来自本地用local 如果来自远程用remote默认为remote
                 name: 'x509User.city',
                 allowBlank: false,
                 blankText: "请选择所在城市/乡镇"
                 }),*/
                new Ext.form.TextField({
                    fieldLabel: '城市/乡镇',
                    name: 'x509User.city',
                    value: record.get("city"),
                    emptyText: "请输入所在城市/乡镇",
                    regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                    regexText: '只能输入数字,字母,中文!',
                    id: 'modifyUser.x509User.city',
                    allowBlank: false,
                    blankText: "不能为空，请正确填写所在城市/乡镇"
                }),
                new Ext.form.TextField({
                    fieldLabel: '公司/团体',
                    allowBlank: false,
                    value: record.get("organization"),
                    regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                    regexText: '只能输入数字,字母,中文!',
                    blankText: "不能为空，请正确填写",
                    name: 'x509User.organization'
                }),
                new Ext.form.TextField({
                    fieldLabel: '部门/机构',
                    allowBlank: false,
                    value: record.get("institution"),
                    regex: /^[a-zA-Z0-9\u4e00-\u9fa5]+$/,
                    regexText: '只能输入数字,字母,中文!',
                    blankText: "不能为空，请正确填写",
                    name: 'x509User.institution'
                }),

                new Ext.form.TextField({
                    fieldLabel: '联系电话',
                    name: 'x509User.phone',
                    regex: /^(1[3,5,8,7]{1}[\d]{9})|(((400)-(\d{3})-(\d{4}))|^((\d{7,8})|(\d{4}|\d{3})-(\d{7,8})|(\d{4}|\d{3})-(\d{3,7,8})-(\d{4}|\d{3}|\d{2}|\d{1})|(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1}))$)$/,
                    regexText: '请输入正确的电话号或手机号',
                    value: record.get("phone"),
                    allowBlank: false,
                    blankText: "联系电话"
                }),
                new Ext.form.TextField({
                    fieldLabel: '联系地址',
                    name: 'x509User.address',
                    value: record.get("address"),
                    allowBlank: false,
                    blankText: "联系地址"
                }),
                new Ext.form.TextField({
                    fieldLabel: '电子邮件',
                    regex: /^[0-9a-zA-Z_\-\.]+@[0-9a-zA-Z_\-]+(\.[0-9a-zA-Z_\-]+)*$/,
                    regexText: '请输入有效的邮件地址',
                    name: 'x509User.userEmail',
                    value: record.get("userEmail"),
                    allowBlank: false,
                    blankText: "电子邮件"
                }),
                new Ext.form.TextField({
                    fieldLabel: '警员编号',
                    emptyText: "请输入警员编号",
                    value: record.get("employeeCode"),
                    name: 'x509User.employeeCode',
                    allowBlank: false,
                    blankText: "警员编号"
                }),
                new Ext.form.ComboBox({
                    fieldLabel: 'CSP设备类型',
                    emptyText: '请选择写入证书设备类型',
                    typeAhead: true,
                    editable: false,
                    triggerAction: 'all',
                    forceSelection: true,
                    mode: 'local',
                    id: 'modifyUser_x509User_smartCard_type',
                    store: smart_card_store,
                    valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                    displayField: 'name',
                    allowBlank: false,
                    blankText: "请选择写入证书设备类型",
                    listeners: {
                        afterRender: function () {
                            this.setValue(smart_card_store.getAt(0).data.id);
                        }
                    }
                }),
                new Ext.form.ComboBox({
                    fieldLabel: 'CSP密钥类型',
                    emptyText: '请选择写入证书密钥类型',
                    typeAhead: true,
                    editable: false,
                    triggerAction: 'all',
                    forceSelection: true,
                    mode: 'local',
                    id: 'modifyUser_x509User_key_type',
                    store: key_type_store,
                    valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                    displayField: 'name',
                    allowBlank: false,
                    blankText: "请选择写入证书密钥类型",
                    listeners: {
                        afterRender: function () {
                            this.setValue(key_type_store.getAt(1).data.id);
                        }
                    }
                }),
                new Ext.form.TextField({
                    fieldLabel: 'CSP容器名称',
                    emptyText: '请输入导入硬件容器名称',
                    allowBlank: false,
                    value:"KingTrustVPN",
                    id: 'modifyUser_x509User_smartCard_container',
                    blankText: "请输入导入硬件容器名称"
                }),
                new Ext.form.ComboBox({
                    fieldLabel: 'CSP加密设备',
                    emptyText: 'CSP加密设备',
                    typeAhead: true,
                    triggerAction: 'all',
                    forceSelection: true,
                    mode: 'local',
                    id: "modifyUser_x509User_smartCard_csp",
                    editable: false,
                    store: cspProvider_store,
                    valueField: 'value',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                    displayField: 'value',//下拉框显示内容
                    allowBlank: false,
                    blankText: "请选择CSP加密设备"
                })
            ]
        });
        var win = new Ext.Window({
            title: "证书更新",
            width: 650,
            layout: 'fit',
            height: 450,
            modal: true,
            items: formPanel,
            bbar: [
                '->',
                {
                    id: 'insert_win.info',
                    text: '证书更新',
                    handler: function () {
                        if (formPanel.form.isValid()) {
                            formPanel.getForm().submit({
                                url: '../../X509UserAction_modifyUser.action',
                                timeout: 20 * 60 * 1000,
                                params: {DN: record.get("dn")},
                                method: 'POST',
                                waitTitle: '系统提示',
                                waitMsg: '正在连接...',
                                success: function () {
                                    var csp = Ext.getCmp("modifyUser_x509User_smartCard_csp").getValue();
                                    var type = Ext.getCmp("modifyUser_x509User_smartCard_type").getRawValue();
                                    var container = Ext.getCmp("modifyUser_x509User_smartCard_container").getValue();
                                    var key_type = Ext.getCmp("modifyUser_x509User_key_type").getRawValue();
                                    Ext.Ajax.request({
                                        url: "../../X509UserAction_modifyUserSmartCard.action",
                                        waitTitle: '请等待',
                                        waitMsg: '正在提交',
                                        params: {DN: record.get("dn"), type: type},
                                        success: function (res, p) {
                                            getDownUrl(record.get("dn"), record.get("cn"), csp, type, container, ZdActivex, key_type);
                                            grid_panel.getStore().reload();
                                            win.close();
                                        },
                                        failure: function (result) {
                                            Ext.Msg.alert("提示", "更新失败!");
                                        }
                                    });
                                },
                                failure: function () {
                                    Ext.MessageBox.show({
                                        title: '信息',
                                        width: 250,
                                        msg: '更新失败，请与管理员联系!',
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
                }, {
                    text: '重置',
                    handler: function () {
                        formPanel.getForm().reset();
                    }
                }
            ]
        }).show();
    }
};


/**
 * 恢复用户证书
 */
function restoreUser() {
    var grid = Ext.getCmp('grid.info');
    var recode = grid.getSelectionModel().getSelected();
    var status = recode.get("certStatus")
    var status_v;
    if (status == "0") {
        var certType = recode.get("certType")
        status_v = "<font color='green'>已发"+certType+"证</font>";
    } else if (status == "1") {
        status_v = "<font color='red'>已吊销</font>";
    }

    var DN = recode.get("dn");
    var cn = recode.get("cn");

    var ZdActivex = document.getElementById("ZdActivex");


    var cspProvider = ZdActivex.EnumCspProvider();

//   alert(cspProvider);

//    var Json = eval(testJson);//错误的转换方式
    var Json = eval("(" + cspProvider + ")");

    var cspProvider_store = new Ext.data.JsonStore({
        data: Json,
        totalProperty: "total",
        root: "rows",
        fields: ['value']
    });

    var smart_card = [
        ['TFCard', 'TFCard'],
        ['USBKey', "USBKey"]
    ];
    var smart_card_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: smart_card
    });

    var key_type_data = [
        ['签名密钥', "签名密钥"],
        ['交换密钥', '交换密钥']
    ];
    var key_type_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: key_type_data
    });


    var formPanel = new Ext.form.FormPanel({
        frame: true,
        autoScroll: true,
        labelWidth: 100,
        labelAlign: 'right',
        autoWidth: true,
        layout: 'form',
        border: false,
        defaults: {
            width: 250,
            anchor: '95%'
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '姓名',
                value: recode.get("cn")
            }),
            /*  new Ext.form.DisplayField({
             fieldLabel: '签发者',
             value: recode.get("issueCa")
             }),
             new Ext.form.DisplayField({
             fieldLabel: '主题',
             value: recode.get("dn")
             }),*/
            new Ext.form.DisplayField({
                fieldLabel: '身份证',
                value: recode.get("idCard")
            }),
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
            }),
            new Ext.form.DisplayField({
                fieldLabel: '联系电话',
                value: recode.get("phone")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '联系地址',
                value: recode.get("address")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '电子邮件',
                value: recode.get("userEmail")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '警员编号',
                value: recode.get("employeeCode")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '状态',
                value: status_v
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP设备类型',
                emptyText: 'CSP设备类型',
                typeAhead: true,
                editable: false,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: 'restoreUser_smartCard_type',
                store: smart_card_store,
                valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'name',
                allowBlank: false,
                blankText: "请选择设备类型",
                listeners: {
                    afterRender: function () {
                        this.setValue(smart_card_store.getAt(0).data.id);
                    }
                }
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP密钥类型',
                emptyText: '请选择写入证书密钥类型',
                typeAhead: true,
                editable: false,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: 'restoreUser_x509User_key_type',
                store: key_type_store,
                valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'name',
                allowBlank: false,
                blankText: "请选择写入证书密钥类型",
                listeners: {
                    afterRender: function () {
                        this.setValue(key_type_store.getAt(1).data.id);
                    }
                }
            }),
            new Ext.form.TextField({
                fieldLabel: 'CSP容器名称',
                emptyText: 'CSP容器名称',
                allowBlank: false,
                value:"KingTrustVPN",
                id: 'restoreUser_smartCard_container',
                blankText: "请选择设备类型"
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP加密设备',
                emptyText: 'CSP加密设备',
                typeAhead: true,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: "restoreUser_smartCard_csp",
                editable: false,
                store: cspProvider_store,
                valueField: 'value',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'value',//下拉框显示内容
                allowBlank: false,
                blankText: "请选择CSP加密设备"
            })
        ]
    });
    var win = new Ext.Window({
        title: "证书恢复",
        width: 650,
        layout: 'fit',
        height: 450,
        modal: true,
        items: formPanel,
        bbar: [
            '->',
            {
                id: 'insert_win.info',
                text: '证书恢复',
                handler: function () {
                    if (formPanel.form.isValid()) {
                        var csp = Ext.getCmp("restoreUser_smartCard_csp").getValue();
                        var type = Ext.getCmp("restoreUser_smartCard_type").getRawValue();
                        var container = Ext.getCmp("restoreUser_smartCard_container").getValue();
                        var key_type = Ext.getCmp("restoreUser_x509User_key_type").getRawValue();
                        formPanel.getForm().submit({
                            url: "../../X509UserAction_modifyUserSmartCard.action",
                            waitTitle: '请等待',
                            waitMsg: '正在提交',
                            params: {DN: DN, type: type},
                            success: function (form, action) {
                                getDownUrl(DN, cn, csp, type, container, ZdActivex, key_type);
                                grid.getStore().reload();
                                win.close();
                            },
                            failure: function (form, action) {
                                Ext.Msg.alert("提示", "删除失败!");
                            }
                        });
                    } else {
                        Ext.Msg.alert('提示', '请先填写完正确信息');
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


/**
 * 导入证书
 * @param DN
 * @param CN
 * @param csp
 * @param type
 * @param name
 * @param ZdActivex
 */
function getDownUrl(DN, CN, csp, type, name, ZdActivex, keyType) {
    var values = new Array();
    values[0] = "G";
    values[1] = "H";
    values[2] = "I";
    values[3] = "J";
    values[4] = "K";
    values[5] = "L";
    values[6] = "M";
    values[7] = "N";
    values[8] = "O";
    values[9] = "P";
    values[10] = "Q";
    values[11] = "R";
    values[12] = "S";
    values[13] = "T";
    values[14] = "U";
    values[15] = "V";
    values[16] = "W";
    values[17] = "X";
    values[18] = "Y";
    values[19] = "Z";
    values[20] = "C";
    values[21] = "D";
    values[22] = "E";
    values[23] = "F";
    values[24] = "A";
    values[25] = "B";

    var myMask = new Ext.LoadMask(Ext.getBody(), {
        msg: '正在处理,请稍后...',
        removeMask: true //完成后移除
    });
    myMask.show();
    Ext.Ajax.request({
        url: "../../X509UserAction_getUserPfxDownLoadURL.action",
        timeout: 5 * 60 * 1000,
        method: "POST",
        params: {DN: DN, CN: CN},
        success: function (res, action) {
            myMask.hide();
            var respText = Ext.util.JSON.decode(res.responseText);
            var Url = respText.url;
            var cn = respText.cn;
            var fso = new ActiveXObject("Scripting.FileSystemObject");
            var folder = fso.GetSpecialFolder(2);
            try {
                var filePath = folder + "/" + cn + ".pfx";
                var flag = ZdActivex.DownLoadToLocal(Url, filePath);
                if (flag = 1) {
                    if (keyType == "交换密钥") {
                        ZdActivex.ImportExchangePFX(csp, filePath, "", name);
                    } else if (keyType == "签名密钥") {
                        ZdActivex.ImportPFX(csp, filePath, "", name);
                    }
                    if (type == "TFCard") {
                        Ext.Ajax.request({
                            url: "../../X509UserAction_getUserCerDownLoadURL.action",
                            timeout: 5 * 60 * 1000,
                            method: "POST",
                            params: {DN: DN, CN: CN},
                            success: function (res, action) {
                                var respText = Ext.util.JSON.decode(res.responseText);
                                var Url = respText.url;   //下载地址*/
                                for (var i = 0; i < values.length; i++) {
                                    var exist_file = values[i] + ":/SONICOM2.RO";
                                    if (fso.FileExists(exist_file)) {
                                        var path = values[i] + ":/CardTools";
                                        if (fso.FolderExists(path)) {
                                            var f_folder = path+"/SSL";
                                            if (!fso.FolderExists(f_folder)) {
                                                fso.CreateFolder(f_folder);
                                            }
                                            var filePath = f_folder + "/client.crt";  //下载目录文件
                                            ZdActivex.DownLoadToLocal(Url, filePath);
                                            break;
                                        }else{
                                            fso.CreateFolder(path);
                                            var f_folder = path+"/SSL";
                                            if (!fso.FolderExists(f_folder)) {
                                                fso.CreateFolder(f_folder);
                                            }
                                            var filePath = f_folder + "/client.crt";  //下载目录文件
                                            ZdActivex.DownLoadToLocal(Url, filePath);
                                            break;
                                        }
                                    }
                                }
                            },
                            failure: function (res, action) {
                                Ext.Msg.alert("提示", type + " 下载用户证书cer文件失败!");
                            }
                        });
                        Ext.Ajax.request({
                            url: "../../X509UserAction_getUserKeyDownLoadURL.action",
                            timeout: 5 * 60 * 1000,
                            method: "POST",
                            params: {DN: DN, CN: CN},
                            success: function (res, action) {
                                var respText = Ext.util.JSON.decode(res.responseText);
                                var Url = respText.url;    //下载地址
                                for (var i = 0; i < values.length; i++) {
                                    var exist_file = values[i] + ":/SONICOM2.RO";
                                    if (fso.FileExists(exist_file)) {
                                        var path = values[i] + ":/CardTools";
                                        if (fso.FolderExists(path)) {
                                            var f_folder = path + "/SSL";
                                            if (!fso.FolderExists(f_folder)) {
                                                fso.CreateFolder(f_folder);
                                            }
                                            var filePath = f_folder + "/client.key";  //下载目录文件
                                            ZdActivex.DownLoadToLocal(Url, filePath);
                                            break;
                                        } else {
                                            fso.CreateFolder(path);
                                            var f_folder = path + "/SSL";
                                            if (!fso.FolderExists(f_folder)) {
                                                fso.CreateFolder(f_folder);
                                            }
                                            var filePath = f_folder + "/client.key";  //下载目录文件
                                            ZdActivex.DownLoadToLocal(Url, filePath);
                                            break;
                                        }
                                    }
                                }
                            },
                            failure: function (res, action) {
                                Ext.Msg.alert("提示", type + " 下载用户证书Key文件失败!");
                            }
                        });
                    }
                } else {
                    Ext.Msg.alert("提示", type + " 用户证书读取失败!");
                }
            }
            catch (err) {
                Ext.Msg.alert("提示", type + " 用户证书写入失败!");
            }
        },
        failure: function (res, action) {
            myMask.hide();
            Ext.Msg.alert("提示", type + " 用户证书写入失败!");
        }
    });
}

/**
 * 吊销用户证书
 */
function revokeUser() {
    var grid = Ext.getCmp('grid.info');
    var recode = grid.getSelectionModel().getSelected();
    var CN = recode.get("cn");
    var DN = recode.get("dn");
    Ext.Msg.confirm("警告", "确认吊销证书,吊销后证书不可用!", function (sid) {
        if (sid == "yes") {
            Ext.Ajax.request({
                url: '../../X509UserAction_revokeUser.action',
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

/**
 * 重发用户证书
 */
function retryUser() {
    var grid = Ext.getCmp('grid.info');
    var recode = grid.getSelectionModel().getSelected();
    var status = recode.get("certStatus")
    var status_v;
    if (status == "0") {
        var certType = recode.get("certType")
        status_v = "<font color='green'>已发"+certType+"证</font>";
    } else if (status == "1") {
        status_v = "<font color='red'>已吊销</font>";
    }

    var DN = recode.get("dn");
    var cn = recode.get("cn");

    var ZdActivex = document.getElementById("ZdActivex");


    var cspProvider = ZdActivex.EnumCspProvider();

//   alert(cspProvider);

//    var Json = eval(testJson);//错误的转换方式
    var Json = eval("(" + cspProvider + ")");

    var cspProvider_store = new Ext.data.JsonStore({
        data: Json,
        totalProperty: "total",
        root: "rows",
        fields: ['value']
    });

    var smart_card = [
        ['TFCard', 'TFCard'],
        ['USBKey', "USBKey"]
    ];
    var smart_card_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: smart_card
    });

    var key_type_data = [
        ['签名密钥', "签名密钥"],
        ['交换密钥', '交换密钥']
    ];
    var key_type_store = new Ext.data.SimpleStore({
        fields: ['id', 'name'],
        data: key_type_data
    });

    var formPanel = new Ext.form.FormPanel({
        frame: true,
        autoScroll: true,
        labelWidth: 100,
        labelAlign: 'right',
        autoWidth: true,
        layout: 'form',
        border: false,
        defaults: {
            width: 250,
            anchor: '95%'
        },
        items: [
            new Ext.form.DisplayField({
                fieldLabel: '姓名',
                value: recode.get("cn")
            }),
            /*  new Ext.form.DisplayField({
             fieldLabel: '签发者',
             value: recode.get("issueCa")
             }),
             new Ext.form.DisplayField({
             fieldLabel: '主题',
             value: recode.get("dn")
             }),*/
            new Ext.form.DisplayField({
                fieldLabel: '身份证',
                value: recode.get("idCard")
            }),
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
            }),
            new Ext.form.DisplayField({
                fieldLabel: '联系电话',
                value: recode.get("phone")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '联系地址',
                value: recode.get("address")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '电子邮件',
                value: recode.get("userEmail")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '警员编号',
                value: recode.get("employeeCode")
            }),
            new Ext.form.DisplayField({
                fieldLabel: '状态',
                value: status_v
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP设备类型',
                emptyText: 'CSP设备类型',
                typeAhead: true,
                editable: false,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: 'restoreUser_smartCard_type',
                store: smart_card_store,
                valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'name',
                allowBlank: false,
                blankText: "请选择设备类型",
                listeners: {
                    afterRender: function () {
                        this.setValue(smart_card_store.getAt(0).data.id);
                    }
                }
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP密钥类型',
                emptyText: '请选择写入证书密钥类型',
                typeAhead: true,
                editable: false,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: 'restoreUser_x509User_key_type',
                store: key_type_store,
                valueField: 'id',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'name',
                allowBlank: false,
                blankText: "请选择写入证书密钥类型",
                listeners: {
                    afterRender: function () {
                        this.setValue(key_type_store.getAt(1).data.id);
                    }
                }
            }),
            new Ext.form.TextField({
                fieldLabel: 'CSP容器名称',
                emptyText: 'CSP容器名称',
                allowBlank: false,
                value:"KingTrustVPN",
                id: 'restoreUser_smartCard_container',
                blankText: "请选择设备类型"
            }),
            new Ext.form.ComboBox({
                fieldLabel: 'CSP加密设备',
                emptyText: 'CSP加密设备',
                typeAhead: true,
                triggerAction: 'all',
                forceSelection: true,
                mode: 'local',
                id: "restoreUser_smartCard_csp",
                editable: false,
                store: cspProvider_store,
                valueField: 'value',   //下拉框具体的值（例如值为SM，则显示的内容即为‘短信’）
                displayField: 'value',//下拉框显示内容
                allowBlank: false,
                blankText: "请选择CSP加密设备"
            })
        ]
    });
    var win = new Ext.Window({
        title: "证书重发",
        width: 650,
        layout: 'fit',
        height: 450,
        modal: true,
        items: formPanel,
        bbar: [
            '->',
            {
                id: 'insert_win.info',
                text: '证书重发',
                handler: function () {
                    if (formPanel.form.isValid()) {

                        Ext.Msg.confirm("警告", "是否重新签发证书,重发后原有证书不可用!", function (sid) {
                            if (sid == "yes") {
                                var csp = Ext.getCmp("restoreUser_smartCard_csp").getValue();
                                var type = Ext.getCmp("restoreUser_smartCard_type").getRawValue();
                                var container = Ext.getCmp("restoreUser_smartCard_container").getValue();
                                var key_type = Ext.getCmp("restoreUser_x509User_key_type").getRawValue();
                                formPanel.getForm().submit({
                                    url: "../../X509UserAction_modifyUserSmartCard.action",
                                    waitTitle: '请等待',
                                    waitMsg: '正在提交',
                                    params: {DN: DN, type: type},
                                    success: function (form, action) {
                                        Ext.Ajax.request({
                                            url: '../../X509UserAction_retryUser.action',
                                            timeout: 20 * 60 * 1000,
                                            params: {DN: DN, CN: cn},
                                            method: 'POST',
                                            success: function (form, action) {
                                                getDownUrl(DN, cn, csp, type, container, ZdActivex, key_type);
                                                grid.getStore().reload();
                                                win.close();
                                            },
                                            failure: function (result) {
                                                Ext.Msg.alert("提示", "重发证书失败!");
                                            }
                                        });
                                    },
                                    failure: function (form, action) {
                                        Ext.Msg.alert("提示", "删除失败!");
                                    }
                                });
                            }
                        })
                    } else {
                        Ext.Msg.alert('提示', '请先填写完正确信息');
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


    /*  var grid = Ext.getCmp('grid.info');
     var recode = grid.getSelectionModel().getSelected();
     var CN = recode.get("cn");
     var DN = recode.get("dn");
     Ext.Msg.confirm("警告", "是否重新签发证书,重发后原有证书不可用!", function (sid) {
     if (sid == "yes") {
     Ext.Ajax.request({
     url: '../../X509UserAction_retryUser.action',
     timeout: 20 * 60 * 1000,
     params: {DN: DN, CN: CN},
     method: 'POST',
     success: function (form, action) {
     Ext.Msg.alert("提示", "重发证书成功!");
     grid.getStore().reload();
     },
     failure: function (result) {
     Ext.Msg.alert("提示", "重发证书失败!");
     grid.getStore().reload();
     }
     });
     }
     });*/
}


function batchSignUser(store) {
    var grid_panel = Ext.getCmp("grid.info");
    var formPanel = new Ext.form.FormPanel({
        frame: true,
        autoScroll: true,
        labelWidth: 150,
        labelAlign: 'right',
        defaultWidth: 300,
        autoWidth: true,
        fileUpload: true,
        layout: 'form',
        border: false,
        defaults: {
            width: 250,
            allowBlank: false,
            blankText: '该项不能为空！'
        },
        items: [
            {
                id: 'downloadModel.info',
                fieldLabel: '下载',
                xtype: 'button',
                text: '批量导入模板',
                iconCls: 'download',
                handler: function () {
                    downloadModel();
                }
            }, {
                id: 'uploadFile',
                fieldLabel: '批量文件',
                xtype: 'textfield',
                inputType: 'file',
                editable: false,
                allowBlank: true
            }
        ]
    });
    var win = new Ext.Window({
        title: "用户批量导入",
        width: 500,
        layout: 'fit',
        height: 200,
        modal: true,
        items: formPanel,
        bbar: [
            '->',
            {
                id: 'insert_win.info',
                text: '导入',
                handler: function () {
                    var myMask = new Ext.LoadMask(Ext.getBody(), {
                        msg: '正在查询,请稍后...',
                        removeMask: true
                    });
                    myMask.show();
                    if (formPanel.form.isValid()) {
                        formPanel.getForm().submit({
                            url: '../../X509UserBatchImport_batchFlag.action',
                            timeout: 20 * 60 * 1000,
                            method: 'POST',
                            success: function (form, action) {
                                var msg = action.result.msg;
                                myMask.hide();
                                Ext.Msg.confirm("提示", msg, function (sid) {
                                    if (sid == "yes") {
                                        var myMask_execute = new Ext.LoadMask(Ext.getBody(), {
                                            msg: '正在导入,请稍后...',
                                            removeMask: true
                                        });
                                        myMask_execute.show();
                                        formPanel.getForm().submit({
                                            url: '../../X509UserBatchImport_batchImportUser.action',
                                            timeout: 20 * 60 * 1000,
                                            method: "POST",
                                            params: {flag: 'true'},
                                            success: function (form, action) {
                                                myMask_execute.hide();
                                                var msg = action.result.msg;
                                                grid_panel.getStore().reload();
                                                Ext.Msg.alert("提示", msg);
                                                win.close();
                                            },
                                            failure: function (form, action) {
                                                myMask_execute.hide();
                                                var msg = action.result.msg;
                                                Ext.Msg.alert("提示", msg);
                                            }
                                        });
                                    } else {
                                        var myMask_execute = new Ext.LoadMask(Ext.getBody(), {
                                            msg: '正在导入,请稍后...',
                                            removeMask: true
                                        });
                                        myMask_execute.show();
                                        formPanel.getForm().submit({
                                            url: '../../X509UserBatchImport_batchImportUser.action',
                                            timeout: 20 * 60 * 1000,
                                            method: "POST",
                                            params: {flag: 'false'},
                                            success: function (form, action) {
                                                myMask_execute.hide();
                                                var msg = action.result.msg;
                                                grid_panel.getStore().reload();
                                                Ext.Msg.alert("提示", msg);
                                                win.close();
                                            },
                                            failure: function (form, action) {
                                                myMask_execute.hide();
                                                var msg = action.result.msg;
                                                Ext.Msg.alert("提示", msg);
                                            }
                                        });
                                    }
                                });
                            },
                            failure: function (form, action) {
                                var msg = action.result.msg;
                                myMask.hide();
                                Ext.MessageBox.show({
                                    title: '信息',
                                    width: 500,
                                    msg: msg,
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
                            width: 250,
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

function downloadModel() {
    if (!Ext.fly('test')) {
        var frm = document.createElement('form');
        frm.id = 'test';
        frm.style.display = 'none';
        document.body.appendChild(frm);
    };
    Ext.Ajax.request({
        url: '../../X509UserBatchImport_downloadModel.action',
        timeout: 20 * 60 * 1000,
        form: Ext.fly('test'),
        method: 'POST',
        isUpload: true
    });
};

function batchExportUser(){
    Ext.Msg.confirm("确认", "确认导入数据为Excel!", function (sid) {
        if (sid == "yes") {
            Ext.Ajax.request({
                url: '../../X509UserBatchImport_batchExportUser.action',
                timeout: 20 * 60 * 1000,
                method: 'POST',
                success: function (r, o) {
                    var respText = Ext.util.JSON.decode(r.responseText);
                    if (respText.flag == 'false') {
                        Ext.MessageBox.show({
                            title: '信息',
                            width: 250,
                            msg: respText.msg,
                            buttons: Ext.MessageBox.ERROR,
                            buttons: {'ok': '确定'},
                            icon: Ext.MessageBox.ERROR,
                            closable: false
                        });
                    }else{
                        if (!Ext.fly('test')) {
                            var frm = document.createElement('form');
                            frm.id = 'test';
                            frm.style.display = 'none';
                            document.body.appendChild(frm);
                        };
                        Ext.Ajax.request({
                            url: '../../X509UserBatchImport_downloadExportUser.action',
                            timeout: 20 * 60 * 1000,
                            form: Ext.fly('test'),
                            method: 'POST',
                            isUpload: false
                        });
                    }
                },
                failure: function (r, o) {
                    Ext.MessageBox.show({
                        title: '信息',
                        width: 250,
                        msg: "导入数据为Excel失败",
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






