/**
 * Created by IntelliJ IDEA.
 * User: 钱晓盼
 * Date: 11-12-8
 * Time: 上午10:15
 * To change this template use File | Settings | File Templates.
 */
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
            id:'internal.count.info',
            fieldLabel:'连通次数',
            xtype:'textfield',
            name:'count',
            value:2,
            regex:/^([2-9]|[1-9][0-9]{1})$/,
            regexText:'这个数不是2~99',
            emptyText:'请输入2~99之间的数字'
        }],
        buttons:[
            new Ext.Toolbar.Spacer({width:100}),{
            id:'internal.ping.test.info',
            text:'测试',
            handler:function(){
                Ext.getCmp('ping.result.info').setValue('');
                var ip = Ext.getCmp('internal.ip.info').getValue();
                var count = Ext.getCmp('internal.count.info').getValue();
                var progress = Ext.MessageBox.show({
                	id:'internal.messagebox.info',
                    title:'请等待',
                    msg:'ping '+ip+' '+count+'次',
                    progressText:'ping...',
                    progress:true,
                    wait:true,
                    animEl:'internal.ping.test.info',
                    width:300,
                    closable : false,
                    waitConfig:{
                        interval:100
                    }
                });
                if(internal_formPanel.form.isValid()) {
                	internal_formPanel.getForm().submit({
                		url:'../../InterfaceManagerAction_ping.action',
                		method:'POST',
                		success:function(form,action) {
                            var flag = action.result.msg;
                			progress.hide();
                			Ext.getCmp('ping.result.info').setValue(flag);
                		},
                		failure:function(){
                			progress.hide();
                			Ext.getCmp('ping.result.info').setValue('ping失败,联系后台管理员!');
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
        layout:'column',
        items:[{
            columnWidth:.3,
            items:[{
                xtype:'fieldset',

                title:'Ping 连通测试',
                items:[internal_formPanel]
            }]
        },{
            columnWidth:.1,
            items:[{
                xtype:'displayfield',
                width:20
            }]
        },{
            columnWidth:.6,
            items:[{
                xtype:'displayfield',
                id:'ping.result.info'
            }]
        }]
    });
    var port = new Ext.Viewport({
        layout:'fit',
        renderTo:Ext.getBody(),
        items:[panel]
    });
});

