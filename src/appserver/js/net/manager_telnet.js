Ext.onReady(function(){
    var internal_formPanel = new Ext.form.FormPanel({
        plain:true,
        labelWidth:100,
        border:false,
        loadMask : { msg : '正在加载数据，请稍后.....' },
        labelAlign:'right',
        buttonAlign:'left',
        defaults : {
            width : 200,
            allowBlank : false,
            blankText : '该项不能为空！'
        },
        items:[{
            id:'internal.ip.info',
            fieldLabel:'IP地址',
            xtype:'textfield',
            name:'ip',
            regex:/^(((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9]))$/,
            regexText:'这个不是Ip',
            emptyText:'请输入Ip'
        },{
            id:'internal.port.info',
            fieldLabel:'端口',
            xtype:'textfield',
            name:'port',
            regex:/^(6553[0-6]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[1-9])$/,
            regexText:'这个不是端口类型1~65536',
            emptyText:'请输入端口1~65536'
        }],
        buttons:[
            new Ext.Toolbar.Spacer({width:100}),{
            id:'internal.telnet.test.info',
            text:'测试',
            handler:function(){
                var ip = Ext.getCmp('internal.ip.info').getValue();
                var port = Ext.getCmp('internal.port.info').getValue();
                if(internal_formPanel.form.isValid()){
                	internal_formPanel.getForm().submit({
                		url:'../../InterfaceManagerAction_telnet.action',
                		method :'POST',
                		success:function(form,action){
                			var flag = action.result.msg;
                			Ext.MessageBox.show({
                				title:'信息',
                				msg:flag,
                				animEl:'internal.telnet.test.info',
                				width:200,
                				buttons:Ext.Msg.OK,
                				buttons:{'ok':'确定'},
                				icon:Ext.MessageBox.INFO,
                				closable:false
                			});
                		},
                		failure:function(){
                			
                		}
                	});
                }
            }
        }]
    });

    var panel = new Ext.Panel({
        frame:true,
        border:false,
        width:500,
        autoScroll:true,
        items:[{
            xtype:'fieldset',
            title:'Telnet 端口测试',
            items:[internal_formPanel]
        }]
    });
    var port = new Ext.Viewport({
        layout:'fit',
        renderTo:Ext.getBody(),
        items:[panel]
    });
});