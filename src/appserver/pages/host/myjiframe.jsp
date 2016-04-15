<%@ page language="java"  pageEncoding="utf-8"%>

<%@ page import = "com.hzih.ca.myjfree.CpuBean,
                    com.hzih.ca.myjfree.LiuLiangBean,
                    com.hzih.ca.myjfree.LiuLiangBean2,
                    com.hzih.ca.myjfree.MonitorInfoList,
                    org.jfree.chart.ChartFactory,
                    org.jfree.chart.JFreeChart,
                    org.jfree.chart.axis.DateAxis,
                    org.jfree.chart.axis.DateTickUnit,
                    org.jfree.chart.axis.ValueAxis,
                    org.jfree.chart.plot.XYPlot,
                    org.jfree.chart.renderer.xy.XYLineAndShapeRenderer"%>
<%@ page import="org.jfree.chart.servlet.ServletUtilities" %>
<%@ page import="org.jfree.data.time.*" %>
<%@ page import="org.jfree.data.xy.XYDataset" %>
<%@ page import="java.awt.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.ArrayList" %>
<%--<%@ page import="java.util.Calendar" %>--%>
<%@ page import="java.util.GregorianCalendar" %>

<%

    //-----------------------------------------------------------------------------------------------------------------------------流量新
    TimeSeries timeseries3 = new TimeSeries("in",Second.class);
    TimeSeries timeseries3Tx = new TimeSeries("out",Second.class);
    GregorianCalendar gc3 = new GregorianCalendar();
//    int year3 = gc3.get(Calendar.YEAR);
//    int month3 = gc3.get(Calendar.MONTH);
//    int day3 = gc3.get(Calendar.DATE);
//    int hour3 = gc3.get(Calendar.HOUR_OF_DAY);
//    int minute3 = gc3.get(Calendar.MINUTE);
//    int second3 = gc3.get(Calendar.SECOND);

//    timeseries3.addOrUpdate(new Second(second3,new Minute()), Math.random()*100);
//    for(int i=1;i<=6;i++) {
//        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute()), Math.random()*100);
//    }
//    for(int i=1;i<=6;i++) {
//        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-1,new Hour())), Math.random()*100);
//    }
//    for(int i=1;i<=6;i++) {
//        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-2,new Hour())), Math.random()*100);
//    }
//    for(int i=1;i<=6;i++) {
//        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-3,new Hour())), Math.random()*100);
//    }
//    for(int i=1;i<=6;i++) {
//        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-4,new Hour())), Math.random()*100);
//    }
//    for(int i=1;i<=6;i++) {
//        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-5,new Hour())), Math.random()*100);
//    }
//    timeseries3.addOrUpdate(new Second(second3,new Minute(miniute3-5,new Hour())), Math.random()*100);
    ArrayList<LiuLiangBean2> liuLiangBean2List = MonitorInfoList.liuLiangBean2ListRX;
    ArrayList<LiuLiangBean2> liuLiangBean2ListTX = MonitorInfoList.liuLiangBean2ListTX;
    if(liuLiangBean2List.size()>0&&(liuLiangBean2List.get(liuLiangBean2List.size()-1).getCurrentMillis()-liuLiangBean2List.get(0).getCurrentMillis())<=(1000*60*5+1000*50)){
        timeseries3.addOrUpdate(new Second(liuLiangBean2List.get(0).getSecond(),new Minute(liuLiangBean2List.get(liuLiangBean2List.size()-1).getMinute()-6,liuLiangBean2List.get(0).getHour())), 0);
        timeseries3.addOrUpdate( new Second(liuLiangBean2List.get(0).getSecond()-1,new Minute(liuLiangBean2List.get(0).getMinute(),liuLiangBean2List.get(0).getHour())), 0);
    }
    if(liuLiangBean2ListTX.size()>0&&(liuLiangBean2ListTX.get(liuLiangBean2ListTX.size()-1).getCurrentMillis()-liuLiangBean2ListTX.get(0).getCurrentMillis())<=(1000*60*5+1000*50)){
        timeseries3Tx.addOrUpdate(new Second(liuLiangBean2ListTX.get(0).getSecond(),new Minute(liuLiangBean2ListTX.get(liuLiangBean2ListTX.size()-1).getMinute()-6,liuLiangBean2ListTX.get(0).getHour())), 0);
        timeseries3Tx.addOrUpdate(new Second(liuLiangBean2ListTX.get(0).getSecond()-1,new Minute(liuLiangBean2ListTX.get(0).getMinute(),liuLiangBean2ListTX.get(0).getHour())), 0);
    }

    double rr = 100;
    double tt = 100;
    for(LiuLiangBean2 LiuLiangBean :liuLiangBean2List){
        timeseries3.addOrUpdate(new Second(LiuLiangBean.getSecond(),new Minute( LiuLiangBean.getMinute(), LiuLiangBean.getHour() )) , LiuLiangBean.getLiuliangNum());
        if( LiuLiangBean.getLiuliangNum()>100 && LiuLiangBean.getLiuliangNum()>rr) {
            rr=200;
            if(LiuLiangBean.getLiuliangNum()>200 && LiuLiangBean.getLiuliangNum()>rr) {
                rr=300;
                if(LiuLiangBean.getLiuliangNum()>300 && LiuLiangBean.getLiuliangNum()>rr) {
                    rr=400;
                    if(LiuLiangBean.getLiuliangNum()>400 && LiuLiangBean.getLiuliangNum()>rr) {
                        rr=500;
                        if(LiuLiangBean.getLiuliangNum()>500 && LiuLiangBean.getLiuliangNum()>rr) {
                            rr=600;
                            if(LiuLiangBean.getLiuliangNum()>600 && LiuLiangBean.getLiuliangNum()>rr) {
                                rr=700;
                                if(LiuLiangBean.getLiuliangNum()>700 && LiuLiangBean.getLiuliangNum()>rr) {
                                    rr=800;
                                    if(LiuLiangBean.getLiuliangNum()>800 && LiuLiangBean.getLiuliangNum()>rr) {
                                        rr=900;
                                        if(LiuLiangBean.getLiuliangNum()>900 && LiuLiangBean.getLiuliangNum()>rr) {
                                            rr=1000;
                                            if(LiuLiangBean.getLiuliangNum()>1000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                rr=1500;
                                                if(LiuLiangBean.getLiuliangNum()>1500 && LiuLiangBean.getLiuliangNum()>rr) {
                                                    rr=2000;
                                                    if(LiuLiangBean.getLiuliangNum()>2000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                        rr=3000;
                                                        if(LiuLiangBean.getLiuliangNum()>3000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                            rr=4000;
                                                            if(LiuLiangBean.getLiuliangNum()>4000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                rr=5000;
                                                                if(LiuLiangBean.getLiuliangNum()>5000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                    rr=10000;
                                                                    if(LiuLiangBean.getLiuliangNum()>10000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                        rr=15000;
                                                                        if(LiuLiangBean.getLiuliangNum()>10000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                            rr=20000;
                                                                            if(LiuLiangBean.getLiuliangNum()>20000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                                rr=40000;
                                                                                if(LiuLiangBean.getLiuliangNum()>40000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                                    rr=60000;
                                                                                    if(LiuLiangBean.getLiuliangNum()>60000 && LiuLiangBean.getLiuliangNum()>rr) {
                                                                                        rr=100000;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for(LiuLiangBean2 LiuLiangBean :liuLiangBean2ListTX){
        timeseries3Tx.addOrUpdate(new Second(LiuLiangBean.getSecond(),new Minute( LiuLiangBean.getMinute(), LiuLiangBean.getHour() )) , LiuLiangBean.getLiuliangNum());
        if( LiuLiangBean.getLiuliangNum()>100  && LiuLiangBean.getLiuliangNum()>tt) {
            tt=200;
            if(LiuLiangBean.getLiuliangNum()>200 && LiuLiangBean.getLiuliangNum()>tt) {
                tt=300;
                if(LiuLiangBean.getLiuliangNum()>300 && LiuLiangBean.getLiuliangNum()>tt) {
                    tt=400;
                    if(LiuLiangBean.getLiuliangNum()>400 && LiuLiangBean.getLiuliangNum()>tt) {
                        tt=500;
                        if(LiuLiangBean.getLiuliangNum()>500 && LiuLiangBean.getLiuliangNum()>tt) {
                            tt=600;
                            if(LiuLiangBean.getLiuliangNum()>600 && LiuLiangBean.getLiuliangNum()>tt) {
                                tt=700;
                                if(LiuLiangBean.getLiuliangNum()>700 && LiuLiangBean.getLiuliangNum()>tt) {
                                    tt=800;
                                    if(LiuLiangBean.getLiuliangNum()>800 && LiuLiangBean.getLiuliangNum()>tt) {
                                        tt=900;
                                        if(LiuLiangBean.getLiuliangNum()>900 && LiuLiangBean.getLiuliangNum()>tt) {
                                            tt=1000;
                                            if(LiuLiangBean.getLiuliangNum()>1000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                tt=1500;
                                                if(LiuLiangBean.getLiuliangNum()>1500 && LiuLiangBean.getLiuliangNum()>tt) {
                                                    tt=2000;
                                                    if(LiuLiangBean.getLiuliangNum()>2000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                        tt=3000;
                                                        if(LiuLiangBean.getLiuliangNum()>3000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                            tt=4000;
                                                            if(LiuLiangBean.getLiuliangNum()>4000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                tt=5000;
                                                                if(LiuLiangBean.getLiuliangNum()>5000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                    tt=10000;
                                                                    if(LiuLiangBean.getLiuliangNum()>10000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                        tt=15000;
                                                                        if(LiuLiangBean.getLiuliangNum()>15000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                            tt=20000;
                                                                            if(LiuLiangBean.getLiuliangNum()>20000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                                tt=40000;
                                                                                if(LiuLiangBean.getLiuliangNum()>40000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                                    tt=60000;
                                                                                    if(LiuLiangBean.getLiuliangNum()>60000 && LiuLiangBean.getLiuliangNum()>tt) {
                                                                                        tt=10000;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if(tt>rr) {
        rr=tt;
    }

    TimeSeriesCollection timeseriescollection3 = new TimeSeriesCollection();
    timeseriescollection3.addSeries(timeseries3);
    timeseriescollection3.addSeries(timeseries3Tx);

//    SimpleDateFormat frm = new SimpleDateFormat("k:mm");

    XYDataset xydataset3 = timeseriescollection3;
    JFreeChart jfreechart3 = ChartFactory.createTimeSeriesChart("netflux", "time", "flux MB/second", xydataset3, true, true, true);
    XYPlot xyplot3 = (XYPlot) jfreechart3.getPlot();
    xyplot3.setBackgroundPaint(Color.black);      //设置背景颜色
    xyplot3.setDomainGridlinePaint(Color.green);  //设置网格竖线颜色
    xyplot3.setRangeGridlinePaint(Color.green);   //设置网格横线颜色
    XYLineAndShapeRenderer xylinerenderer3=(XYLineAndShapeRenderer)xyplot3.getRenderer();
    xylinerenderer3.setSeriesPaint(0, new Color(0, 255 ,0 ));
    xylinerenderer3.setSeriesPaint(1, new Color(255, 0 ,0 ));

    DateAxis dateaxis3 = (DateAxis) xyplot3.getDomainAxis();//获取x轴
    dateaxis3.setDateFormatOverride(new SimpleDateFormat("HH:mm"));
    dateaxis3.setTickUnit(new DateTickUnit(DateTickUnit.MINUTE, 1));

    // frame1=new ChartPanel(jfreechart,true);
    dateaxis3.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题
    dateaxis3.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题

    ValueAxis rangeAxis3=xyplot3.getRangeAxis();//获取y轴
    rangeAxis3.setRange(0, rr);
//    rangeAxis.setAutoRange(true);
    rangeAxis3.setLabelFont(new Font("黑体",Font.BOLD,15));
    jfreechart3.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));
    jfreechart3.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
    String filename3 = ServletUtilities.saveChartAsPNG(jfreechart3, 500, 360, null, session);
    String graphURL3 = request.getContextPath() + "/DisplayChart?filename=" + filename3;

%>

<html>
<head>
    <title>My JSP 'index.jsp' starting page</title>
    <meta http-equiv="pragma" content="no-cache">
    <meta http-equiv="cache-control" content="no-cache">
    <meta http-equiv="expires" content="0">
    <meta http-equiv="keywords" content="keyword1,keyword2,keyword3">
    <meta http-equiv="description" content="This is my page">
    <!--
     <link rel="stylesheet" type="text/css" href="styles.css">
     -->

    <script type="text/javascript">
        function setDX() {
            var bodywidth = document.body.clientWidth;
            var imghight = document.body.clientHeight;
            document.getElementById("img4").width=bodywidth;
            document.getElementById("img4").height=imghight;
        }
        //        location.href="myjfreezhexian.jsp";
        //        setTimeout("self.location.reload();",1000);
        //        setTimeout("location.href='myjfreezhexian.jsp?flagts=1'",1000);
        setTimeout("document.myform.submit();",10000);
    </script>
</head>

<body onload="setDX()">

<img id="img4" src="<%= graphURL3 %>"  border=0 >
<form name="myform" method="post" action="myjiframe.jsp">
    <input type="hidden" name="flagts" value="1">
</form>


</body>
</html>