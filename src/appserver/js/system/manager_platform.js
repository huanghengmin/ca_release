/**
 * 平台管理 重启 关闭等
 */
Ext.onReady(function(){
    Ext.BLANK_IMAGE_URL = '../../js/ext/resources/images/default/s.gif';
    Ext.QuickTips.init();
    Ext.form.Field.prototype.msgTarget = 'side';
    var systemRestartPanel = new Ext.Panel({
        id:'sysRestart.info',
        html:"<a href='javascript:;' onclick='systemRestart();'><img src='../../img/icon/systemRestart.png' alt='重启系统' title='重新启动中监控平台!' /></a>"
    });
    var equipmentRestartPanel = new Ext.Panel({
        id:'equiRestart.info',
        html:"<a href='javascript:;' onclick='equipmentRestart();'><img src='../../img/icon/equipmentRestart.png' alt='重启设备' title='重新启动当前运行的设备!'/></a>"
    });
    var equipmentShutdownPanel = new Ext.Panel({
        id:'equiShutdown.info',
        html:"<a href='javascript:;' onclick='equipmentShutdown();'><img src='../../img/icon/equipmentShutdown.png' alt='关闭设备' title='关闭当前运行的设备!' /></a>"
    });
    new Ext.Viewport({
        renderTo:Ext.getBody(),
        layout:'fit',
        items:[
            {
                layout:'form',
                frame:true,
                autoScroll:true,
                items:[
                    {plain:true,height:50},
                    {
                        layout:'column',
                        plain:true,
                        items:[
                            {items:[{width:1,html:"&nbsp;&nbsp;&nbsp;&nbsp;"}],columnWidth:.2},
                            {items:[systemRestartPanel],columnWidth:.25},
                            {items:[equipmentRestartPanel],columnWidth:.25},
                            {items:[equipmentShutdownPanel],columnWidth:.25}
                        ]
                    }
                ]
            }
        ]
    });
});


function systemRestart(){
    Ext.MessageBox.show({
        title:"信息",
        width:250,
        msg:"确定要重启系统吗?",
        animEl:'sysRestart.info',
        icon:Ext.MessageBox.WARNING,
        buttons:{'ok':'确定','no':'取消'},
        fn:function(e){
            if(e=='ok'){
                var myMask = new Ext.LoadMask(Ext.getBody(), {
                    msg: '正在重启系统,请稍后...',
                    removeMask: true //完成后移除
                });
                myMask.show();
                Ext.Ajax.request({
                    url:'../../PlatformAction_sysRestart.action',
                    method:'POST',
                    success:function(r,o){
                        var respText = Ext.util.JSON.decode(r.responseText);
                        var msg = respText.msg;
                        myMask.hide();
                        Ext.MessageBox.show({
                            title:"信息",
                            msg:msg,
                            animEl:'sysRestart.info',
                            icon:Ext.MessageBox.INFO,
                            buttons:{'ok':'确定'}
                        });
                    }
                });
            }
        }
    });
}
function equipmentRestart(){
    Ext.MessageBox.show({
        title:"信息",
        width:250,
        msg:"确定要重启设备吗?",
        animEl:'equipRestart.info',
        icon:Ext.MessageBox.WARNING,
        buttons:{'ok':'确定','no':'取消'},
        fn : function(e){
            if(e=='ok'){
                var myMask = new Ext.LoadMask(Ext.getBody(), {
                    msg: '正在重启设备,请稍后...',
                    removeMask: true //完成后移除
                });
                myMask.show();
                Ext.Ajax.request({
                    url:'../../PlatformAction_equipRestart.action',
                    method:'POST',
                    success:function(r,o){
                        myMask.hide();
                        var respText = Ext.util.JSON.decode(r.responseText);
                        var msg = respText.msg;
                        Ext.MessageBox.show({
                            title:"信息",
                            msg:msg,
                            animEl:'equipRestart.info',
                            buttons:{'ok':'确定'}
                        });
                    }
                });
            }
        }
    });
}

function equipmentShutdown(){
    Ext.MessageBox.show({
        title:"信息",
        width:250,
        msg:"确定要关闭设备吗?",
        animEl:'equipShutdown.info',
        icon:Ext.MessageBox.WARNING,
        buttons:{'ok':'确定','no':'取消'},
        fn:function(e){
            if(e=='ok'){
                var myMask = new Ext.LoadMask(Ext.getBody(), {
                    msg: '正在关闭设备,请稍后...',
                    removeMask: true //完成后移除
                });
                myMask.show();
                Ext.Ajax.request({
                    url:'../../PlatformAction_equipShutdown.action',
                    method:'POST',
                    success:function(r,o){
                        myMask.hide();
                        var respText = Ext.util.JSON.decode(r.responseText);
                        var msg = respText.msg;
                        Ext.MessageBox.show({
                            title:"信息",
                            msg:msg,
                            animEl:'equipShutdown.info',
                            icon:Ext.MessageBox.INFO,
                            buttons:{'ok':'确定'}
                        });
                    }
                });
            }
        }
    });
}