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
<%@ page import="java.util.Calendar" %>
<%@ page import="java.util.GregorianCalendar" %>
<%@ page import="java.io.File" %>
<%@ page import="com.hzih.ca.utils.StringContext" %>

<%
    File file = new File(StringContext.tempPath);
    File[] list = file.listFiles();
    for(File f : list ) {
        String fname = f.getName();
        if(fname.indexOf("jfreechart-")==0) {
            f.delete();
        }
    }

//    TimeSeries timeseries = new TimeSeries("IN",Minute.class);
//    TimeSeries timeseriesTx = new TimeSeries("OUT",Minute.class);
//    GregorianCalendar gc = new GregorianCalendar();
//    int year = gc.get(Calendar.YEAR);
//    int month = gc.get(Calendar.MONTH);
//    int day = gc.get(Calendar.DATE);
//    int hour = gc.get(Calendar.HOUR_OF_DAY);
//    int minute = gc.get(Calendar.MINUTE);
//    int second = gc.get(Calendar.SECOND);
//
//    ArrayList<LiuLiangBean> liuLiangBeanList = MonitorInfoList.liuLiangBeanListRX;
//    ArrayList<LiuLiangBean> liuLiangBeanListTX = MonitorInfoList.liuLiangBeanListTX;
//    if(liuLiangBeanList.size()>0&&(liuLiangBeanList.get(liuLiangBeanList.size()-1).getCurrentMillis()-liuLiangBeanList.get(0).getCurrentMillis())<=(1000*60*59)){
//        timeseries.addOrUpdate(new Minute(minute,new Hour(hour-1,new Day())), 0);
//        timeseries.addOrUpdate(new Minute( liuLiangBeanList.get(0).getMinute()-1, liuLiangBeanList.get(0).getHour()), 0);
//    }
//    if(liuLiangBeanListTX.size()>0&&(liuLiangBeanListTX.get(liuLiangBeanListTX.size()-1).getCurrentMillis()-liuLiangBeanListTX.get(0).getCurrentMillis())<=(1000*60*59)){
//        timeseriesTx.addOrUpdate(new Minute(minute,new Hour(hour-1,new Day())), 0);
//        timeseriesTx.addOrUpdate(new Minute( liuLiangBeanListTX.get(0).getMinute()-1, liuLiangBeanListTX.get(0).getHour()), 0);
//    }
//
//    session.setAttribute("liuLiangBeanList",liuLiangBeanList);
//    session.setAttribute("liuLiangBeanListTX",liuLiangBeanListTX);
//    double rr = 100;
//    double tt = 100;
//    for(LiuLiangBean LiuLiangBean :liuLiangBeanList){
//        timeseries.addOrUpdate(new Minute( LiuLiangBean.getMinute(), LiuLiangBean.getHour() ), LiuLiangBean.getLiuliangNum());
//        if( LiuLiangBean.getLiuliangNum()>100 && LiuLiangBean.getLiuliangNum()>rr) {
//            rr=200;
//            if(LiuLiangBean.getLiuliangNum()>200 && LiuLiangBean.getLiuliangNum()>rr) {
//                rr=300;
//                if(LiuLiangBean.getLiuliangNum()>300 && LiuLiangBean.getLiuliangNum()>rr) {
//                    rr=400;
//                    if(LiuLiangBean.getLiuliangNum()>400 && LiuLiangBean.getLiuliangNum()>rr) {
//                        rr=500;
//                        if(LiuLiangBean.getLiuliangNum()>500 && LiuLiangBean.getLiuliangNum()>rr) {
//                            rr=600;
//                            if(LiuLiangBean.getLiuliangNum()>600 && LiuLiangBean.getLiuliangNum()>rr) {
//                                rr=700;
//                                if(LiuLiangBean.getLiuliangNum()>700 && LiuLiangBean.getLiuliangNum()>rr) {
//                                    rr=800;
//                                    if(LiuLiangBean.getLiuliangNum()>800 && LiuLiangBean.getLiuliangNum()>rr) {
//                                        rr=900;
//                                        if(LiuLiangBean.getLiuliangNum()>900 && LiuLiangBean.getLiuliangNum()>rr) {
//                                            rr=1000;
//                                            if(LiuLiangBean.getLiuliangNum()>1000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                rr=1500;
//                                                if(LiuLiangBean.getLiuliangNum()>1500 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                    rr=2000;
//                                                    if(LiuLiangBean.getLiuliangNum()>2000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                        rr=3000;
//                                                        if(LiuLiangBean.getLiuliangNum()>3000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                            rr=4000;
//                                                            if(LiuLiangBean.getLiuliangNum()>4000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                rr=5000;
//                                                                if(LiuLiangBean.getLiuliangNum()>5000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                    rr=10000;
//                                                                }
//                                                            }
//                                                        }
//                                                    }
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//    }
//    for(LiuLiangBean LiuLiangBean :liuLiangBeanListTX){
//        timeseriesTx.addOrUpdate(new Minute( LiuLiangBean.getMinute(), LiuLiangBean.getHour() ), LiuLiangBean.getLiuliangNum());
//        if( LiuLiangBean.getLiuliangNum()>100  && LiuLiangBean.getLiuliangNum()>tt) {
//            tt=200;
//            if(LiuLiangBean.getLiuliangNum()>200 && LiuLiangBean.getLiuliangNum()>tt) {
//                tt=300;
//                if(LiuLiangBean.getLiuliangNum()>300 && LiuLiangBean.getLiuliangNum()>tt) {
//                    tt=400;
//                    if(LiuLiangBean.getLiuliangNum()>400 && LiuLiangBean.getLiuliangNum()>tt) {
//                        tt=500;
//                        if(LiuLiangBean.getLiuliangNum()>500 && LiuLiangBean.getLiuliangNum()>tt) {
//                            tt=600;
//                            if(LiuLiangBean.getLiuliangNum()>600 && LiuLiangBean.getLiuliangNum()>tt) {
//                                tt=700;
//                                if(LiuLiangBean.getLiuliangNum()>700 && LiuLiangBean.getLiuliangNum()>tt) {
//                                    tt=800;
//                                    if(LiuLiangBean.getLiuliangNum()>800 && LiuLiangBean.getLiuliangNum()>tt) {
//                                        tt=900;
//                                        if(LiuLiangBean.getLiuliangNum()>900 && LiuLiangBean.getLiuliangNum()>tt) {
//                                            tt=1000;
//                                            if(LiuLiangBean.getLiuliangNum()>1000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                tt=1500;
//                                                if(LiuLiangBean.getLiuliangNum()>1500 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                    tt=2000;
//                                                    if(LiuLiangBean.getLiuliangNum()>2000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                        tt=3000;
//                                                        if(LiuLiangBean.getLiuliangNum()>3000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                            tt=4000;
//                                                            if(LiuLiangBean.getLiuliangNum()>4000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                tt=5000;
//                                                                if(LiuLiangBean.getLiuliangNum()>5000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                    tt=10000;
//                                                                }
//                                                            }
//                                                        }
//                                                    }
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//    }
//    if(tt>rr) {
//        rr=tt;
//    }
////    timeseries.add(new Minute(), Math.random()*600);
////    timeseries.addOrUpdate(new Minute(), Math.random() * 600);
////    for(int i=1;i<=60;i++){
////        timeseries.add(new Minute(minute-i, new Hour()), Math.random()*600);
////    }
//    TimeSeriesCollection timeseriescollection = new TimeSeriesCollection();
//    timeseriescollection.addSeries(timeseries);
//    timeseriescollection.addSeries(timeseriesTx);
//
//    XYDataset xydataset = timeseriescollection;
//    JFreeChart jfreechart = ChartFactory.createTimeSeriesChart("netflux", "time", "flux MB/minite", xydataset, true, true, true);
//    XYPlot xyplot = (XYPlot) jfreechart.getPlot();
//    xyplot.setBackgroundPaint(Color.black);      //设置背景颜色
//    xyplot.setDomainGridlinePaint(Color.green);  //设置网格竖线颜色
//    xyplot.setRangeGridlinePaint(Color.green);   //设置网格横线颜色
//    XYLineAndShapeRenderer xylinerenderer=(XYLineAndShapeRenderer)xyplot.getRenderer();
//    xylinerenderer.setSeriesPaint(0, new Color(0, 255 ,0 ));
//    xylinerenderer.setSeriesPaint(1, new Color(255, 0 ,0 ));
//
//    DateAxis dateaxis = (DateAxis) xyplot.getDomainAxis();//获取x轴
//    dateaxis.setDateFormatOverride(new SimpleDateFormat("HH:mm"));
////    SimpleDateFormat frm = new SimpleDateFormat("k:mm");
////    dateaxis.setTickUnit(new DateTickUnit(DateTickUnit.MINUTE, 5,frm));
////    Calendar date = Calendar.getInstance();
////    date.set(2013, 2, 2,15,0);
////    Calendar mdate = Calendar.getInstance();
////    mdate.set(2013, 2, 2,15,60);
////    dateaxis.setRange(date.getTime(),mdate.getTime());
//
//
//    // frame1=new ChartPanel(jfreechart,true);
//    dateaxis.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题
//    dateaxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题
//
//    ValueAxis rangeAxis=xyplot.getRangeAxis();//获取y轴
//    rangeAxis.setRange(0, rr);
////    rangeAxis.setAutoRange(true);
//    rangeAxis.setLabelFont(new Font("黑体",Font.BOLD,15));
//    jfreechart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));
//    jfreechart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
//    String filename = ServletUtilities.saveChartAsPNG(jfreechart, 500, 360, null, session);
//    String graphURL = request.getContextPath() + "/DisplayChart?filename=" + filename;

    //---------------------------------------------------------------------------------cpu---------------------------------------------------------------------------------------------------------------

    TimeSeries timeseries2 = new TimeSeries("CPU",
            Minute.class);
    GregorianCalendar gc2 = new GregorianCalendar();
    int year2 = gc2.get(Calendar.YEAR);
    int month2 = gc2.get(Calendar.MONTH);
    int day2 = gc2.get(Calendar.DATE);
    int hour2 = gc2.get(Calendar.HOUR_OF_DAY);
    int miniute2 = gc2.get(Calendar.MINUTE);
    int second2 = gc2.get(Calendar.SECOND);

//    ArrayList<CpuBean> cpuBeanList = (ArrayList<CpuBean>) session.getAttribute("cpuBeanList");
////    String flagts = request.getParameter("flagts");
//    if(null==flagts||null==cpuBeanList) {
//        cpuBeanList = new ArrayList<CpuBean>();
//    }
//    cpuBeanList.add(new CpuBean( miniute2, new Hour(), new SnmpUtil().getCpuUse(), System.currentTimeMillis() ));
//    if(cpuBeanList.size()>1&&(cpuBeanList.get(cpuBeanList.size()-1).getCurrentMillis()-cpuBeanList.get(0).getCurrentMillis())>(1000*60*60)){
//        cpuBeanList.remove(0);
//    }else{
//        timeseries2.addOrUpdate(new Minute(miniute2-60,new Hour()), 0);
//        timeseries2.addOrUpdate(new Minute( cpuBeanList.get(0).getMinute()-1, cpuBeanList.get(0).getHour() ), 0);
//    }
    ArrayList<CpuBean> cpuBeanList = MonitorInfoList.cpuBeanList;
    if(cpuBeanList.size()>0&&(cpuBeanList.get(cpuBeanList.size()-1).getCurrentMillis()-cpuBeanList.get(0).getCurrentMillis())<=(1000*60*59)){
        timeseries2.addOrUpdate(new Minute(miniute2,new Hour(hour2-1,new Day())), 0);
        timeseries2.addOrUpdate(new Minute( cpuBeanList.get(0).getMinute()-1, cpuBeanList.get(0).getHour() ), 0);
    }
    session.setAttribute("cpuBeanList",cpuBeanList);
    for(CpuBean cpuBean :cpuBeanList){
        timeseries2.addOrUpdate(new Minute(cpuBean.getMinute(),cpuBean.getHour()), cpuBean.getCpuNum());
    }
    TimeSeriesCollection timeseriescollection2 = new TimeSeriesCollection();
    timeseriescollection2.addSeries(timeseries2);

    XYDataset xydataset2 = timeseriescollection2;
    JFreeChart jfreechart2 = ChartFactory.createTimeSeriesChart("CPU", "time", "CPU%", xydataset2, true, true, true);
    XYPlot xyplot2 = (XYPlot) jfreechart2.getPlot();
    xyplot2.setBackgroundPaint(Color.black);      //设置背景颜色
    xyplot2.setDomainGridlinePaint(Color.green);  //设置网格竖线颜色
    xyplot2.setRangeGridlinePaint(Color.green);   //设置网格横线颜色
    XYLineAndShapeRenderer xylinerenderer2=(XYLineAndShapeRenderer)xyplot2.getRenderer();
    xylinerenderer2.setSeriesPaint(0, new Color(0, 255 ,0 ));

    DateAxis dateaxis2 = (DateAxis) xyplot2.getDomainAxis();//获取x轴
    dateaxis2.setDateFormatOverride(new SimpleDateFormat("HH:mm"));
//    SimpleDateFormat frm = new SimpleDateFormat("k:mm");
//    dateaxis.setTickUnit(new DateTickUnit(DateTickUnit.MINUTE, 5,frm));
//    Calendar date = Calendar.getInstance();
//    date.set(2013, 2, 2,15,0);
//    Calendar mdate = Calendar.getInstance();
//    mdate.set(2013, 2, 2,15,60);
//    dateaxis.setRange(date.getTime(),mdate.getTime());


    // frame1=new ChartPanel(jfreechart,true);
    dateaxis2.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题
    dateaxis2.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题

    ValueAxis rangeAxis2=xyplot2.getRangeAxis();//获取y轴
    rangeAxis2.setRange(0, 100);
//    rangeAxis.setAutoRange(true);
    rangeAxis2.setLabelFont(new Font("黑体",Font.BOLD,15));
    jfreechart2.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));
    jfreechart2.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
    String filename2 = ServletUtilities.saveChartAsPNG(jfreechart2, 500, 360, null, session);
    String graphURL2 = request.getContextPath() + "/DisplayChart?filename=" + filename2;

//---------------------------------------------------------------------------------内存---------------------------------------------------------------------------------------------------------------
    TimeSeries timeseriesMem = new TimeSeries("internal memory",
            Minute.class);

//    ArrayList<CpuBean> cpuBeanListMem = (ArrayList<CpuBean>) session.getAttribute("cpuBeanListMem");
////    String flagts = request.getParameter("flagts");
//    if(null==flagts||null==cpuBeanListMem) {
//        cpuBeanListMem = new ArrayList<CpuBean>();
//    }
//    cpuBeanListMem.add(new CpuBean( miniute2, new Hour(), new SnmpUtil().getMem(), System.currentTimeMillis() ));
//    if(cpuBeanListMem.size()>1&&(cpuBeanListMem.get(cpuBeanListMem.size()-1).getCurrentMillis()-cpuBeanListMem.get(0).getCurrentMillis())>(1000*60*60)){
//        cpuBeanListMem.remove(0);
//    }else{
//        timeseriesMem.addOrUpdate(new Minute(miniute2-60,new Hour()), 0);
//        timeseriesMem.addOrUpdate(new Minute( cpuBeanListMem.get(0).getMinute()-1, cpuBeanListMem.get(0).getHour() ), 0);
//    }
    ArrayList<CpuBean> cpuBeanListMem = MonitorInfoList.cpuBeanListMem;
    if(cpuBeanListMem!=null){
        if(cpuBeanListMem.size()>0&&(cpuBeanListMem.get(cpuBeanListMem.size()-1).getCurrentMillis()-cpuBeanListMem.get(0).getCurrentMillis())<=(1000*60*59)){
            timeseriesMem.addOrUpdate(new Minute(miniute2,new Hour(hour2-1,new Day())), 0);
            timeseriesMem.addOrUpdate(new Minute( cpuBeanListMem.get(0).getMinute()-1, cpuBeanListMem.get(0).getHour() ), 0);
        }
    }
    session.setAttribute("cpuBeanListMem",cpuBeanListMem);
    for(CpuBean cpuBean :cpuBeanListMem){
        timeseriesMem.addOrUpdate(new Minute(cpuBean.getMinute(),cpuBean.getHour()), cpuBean.getCpuNum());
    }
    TimeSeriesCollection timeseriescollectionMem = new TimeSeriesCollection();
    timeseriescollectionMem.addSeries(timeseriesMem);

    XYDataset xydatasetMem = timeseriescollectionMem;
    JFreeChart jfreechartMem = ChartFactory.createTimeSeriesChart("internal memory", "time", "memory%", xydatasetMem, true, true, true);
    XYPlot xyplotMem = (XYPlot) jfreechartMem.getPlot();
    xyplotMem.setBackgroundPaint(Color.black);      //设置背景颜色
    xyplotMem.setDomainGridlinePaint(Color.green);  //设置网格竖线颜色
    xyplotMem.setRangeGridlinePaint(Color.green);   //设置网格横线颜色
    XYLineAndShapeRenderer xylinerendererMem=(XYLineAndShapeRenderer)xyplotMem.getRenderer();
    xylinerendererMem.setSeriesPaint(0, new Color(0, 255 ,0 ));

    DateAxis dateaxisMem = (DateAxis) xyplotMem.getDomainAxis();//获取x轴
    dateaxisMem.setDateFormatOverride(new SimpleDateFormat("HH:mm"));
//    SimpleDateFormat frm = new SimpleDateFormat("k:mm");
//    dateaxis.setTickUnit(new DateTickUnit(DateTickUnit.MINUTE, 5,frm));
//    Calendar date = Calendar.getInstance();
//    date.set(2013, 2, 2,15,0);
//    Calendar mdate = Calendar.getInstance();
//    mdate.set(2013, 2, 2,15,60);
//    dateaxis.setRange(date.getTime(),mdate.getTime());


    // frame1=new ChartPanel(jfreechart,true);
    dateaxisMem.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题
    dateaxisMem.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题

    ValueAxis rangeAxisMem = xyplotMem.getRangeAxis();//获取y轴
    rangeAxisMem.setRange(0, 100);
//    rangeAxis.setAutoRange(true);
    rangeAxisMem.setLabelFont(new Font("黑体",Font.BOLD,15));
    jfreechartMem.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));
    jfreechartMem.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
    String filenameMem = ServletUtilities.saveChartAsPNG(jfreechartMem, 500, 360, null, session);
    String graphURLMem = request.getContextPath() + "/DisplayChart?filename=" + filenameMem;

//-----------------------------------------------------------------------------------------------------------------------------试验
//    TimeSeries timeseries3 = new TimeSeries("in",Second.class);
//    TimeSeries timeseries3Tx = new TimeSeries("out",Second.class);
//    GregorianCalendar gc3 = new GregorianCalendar();
//    int year3 = gc3.get(Calendar.YEAR);
//    int month3 = gc3.get(Calendar.MONTH);
//    int day3 = gc3.get(Calendar.DATE);
//    int hour3 = gc3.get(Calendar.HOUR_OF_DAY);
//    int minute3 = gc3.get(Calendar.MINUTE);
//    int second3 = gc3.get(Calendar.SECOND);
//
////    timeseries3.addOrUpdate(new Second(second3,new Minute()), Math.random()*100);
////    for(int i=1;i<=6;i++) {
////        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute()), Math.random()*100);
////    }
////    for(int i=1;i<=6;i++) {
////        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-1,new Hour())), Math.random()*100);
////    }
////    for(int i=1;i<=6;i++) {
////        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-2,new Hour())), Math.random()*100);
////    }
////    for(int i=1;i<=6;i++) {
////        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-3,new Hour())), Math.random()*100);
////    }
////    for(int i=1;i<=6;i++) {
////        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-4,new Hour())), Math.random()*100);
////    }
////    for(int i=1;i<=6;i++) {
////        timeseries3.addOrUpdate(new Second(second3-i*10,new Minute(miniute3-5,new Hour())), Math.random()*100);
////    }
////    timeseries3.addOrUpdate(new Second(second3,new Minute(miniute3-5,new Hour())), Math.random()*100);
//    ArrayList<LiuLiangBean2> liuLiangBean2List = MonitorInfoList.liuLiangBean2ListRX;
//    ArrayList<LiuLiangBean2> liuLiangBean2ListTX = MonitorInfoList.liuLiangBean2ListTX;
//    if(liuLiangBean2List.size()>0&&(liuLiangBean2List.get(liuLiangBean2List.size()-1).getCurrentMillis()-liuLiangBean2List.get(0).getCurrentMillis())<=(1000*60*5+1000*50)){
//        timeseries3.addOrUpdate(new Second(liuLiangBean2List.get(0).getSecond(),new Minute(liuLiangBean2List.get(liuLiangBean2List.size()-1).getMinute()-6,liuLiangBean2List.get(0).getHour())), 0);
//        timeseries3.addOrUpdate( new Second(liuLiangBean2List.get(0).getSecond()-1,new Minute(liuLiangBean2List.get(0).getMinute(),liuLiangBean2List.get(0).getHour())), 0);
//    }
//    if(liuLiangBean2ListTX.size()>0&&(liuLiangBean2ListTX.get(liuLiangBean2ListTX.size()-1).getCurrentMillis()-liuLiangBean2ListTX.get(0).getCurrentMillis())<=(1000*60*5+1000*50)){
//        timeseries3Tx.addOrUpdate(new Second(liuLiangBean2ListTX.get(0).getSecond(),new Minute(liuLiangBean2ListTX.get(liuLiangBean2ListTX.size()-1).getMinute()-6,liuLiangBean2ListTX.get(0).getHour())), 0);
//        timeseries3Tx.addOrUpdate(new Second(liuLiangBean2ListTX.get(0).getSecond()-1,new Minute(liuLiangBean2ListTX.get(0).getMinute(),liuLiangBean2ListTX.get(0).getHour())), 0);
//    }
//
//    double rr = 100;
//    double tt = 100;
//    for(LiuLiangBean2 LiuLiangBean :liuLiangBean2List){
//        timeseries3.addOrUpdate(new Second(LiuLiangBean.getSecond(),new Minute( LiuLiangBean.getMinute(), LiuLiangBean.getHour() )) , LiuLiangBean.getLiuliangNum());
//        if( LiuLiangBean.getLiuliangNum()>100 && LiuLiangBean.getLiuliangNum()>rr) {
//            rr=200;
//            if(LiuLiangBean.getLiuliangNum()>200 && LiuLiangBean.getLiuliangNum()>rr) {
//                rr=300;
//                if(LiuLiangBean.getLiuliangNum()>300 && LiuLiangBean.getLiuliangNum()>rr) {
//                    rr=400;
//                    if(LiuLiangBean.getLiuliangNum()>400 && LiuLiangBean.getLiuliangNum()>rr) {
//                        rr=500;
//                        if(LiuLiangBean.getLiuliangNum()>500 && LiuLiangBean.getLiuliangNum()>rr) {
//                            rr=600;
//                            if(LiuLiangBean.getLiuliangNum()>600 && LiuLiangBean.getLiuliangNum()>rr) {
//                                rr=700;
//                                if(LiuLiangBean.getLiuliangNum()>700 && LiuLiangBean.getLiuliangNum()>rr) {
//                                    rr=800;
//                                    if(LiuLiangBean.getLiuliangNum()>800 && LiuLiangBean.getLiuliangNum()>rr) {
//                                        rr=900;
//                                        if(LiuLiangBean.getLiuliangNum()>900 && LiuLiangBean.getLiuliangNum()>rr) {
//                                            rr=1000;
//                                            if(LiuLiangBean.getLiuliangNum()>1000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                rr=1500;
//                                                if(LiuLiangBean.getLiuliangNum()>1500 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                    rr=2000;
//                                                    if(LiuLiangBean.getLiuliangNum()>2000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                        rr=3000;
//                                                        if(LiuLiangBean.getLiuliangNum()>3000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                            rr=4000;
//                                                            if(LiuLiangBean.getLiuliangNum()>4000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                rr=5000;
//                                                                if(LiuLiangBean.getLiuliangNum()>5000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                    rr=10000;
//                                                                    if(LiuLiangBean.getLiuliangNum()>10000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                        rr=15000;
//                                                                        if(LiuLiangBean.getLiuliangNum()>10000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                            rr=20000;
//                                                                            if(LiuLiangBean.getLiuliangNum()>20000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                                rr=40000;
//                                                                                if(LiuLiangBean.getLiuliangNum()>40000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                                    rr=60000;
//                                                                                    if(LiuLiangBean.getLiuliangNum()>60000 && LiuLiangBean.getLiuliangNum()>rr) {
//                                                                                        rr=100000;
//                                                                                    }
//                                                                                }
//                                                                            }
//                                                                        }
//                                                                    }
//                                                                }
//                                                            }
//                                                        }
//                                                    }
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//    }
//    for(LiuLiangBean2 LiuLiangBean :liuLiangBean2ListTX){
//        timeseries3Tx.addOrUpdate(new Second(LiuLiangBean.getSecond(),new Minute( LiuLiangBean.getMinute(), LiuLiangBean.getHour() )) , LiuLiangBean.getLiuliangNum());
//        if( LiuLiangBean.getLiuliangNum()>100  && LiuLiangBean.getLiuliangNum()>tt) {
//            tt=200;
//            if(LiuLiangBean.getLiuliangNum()>200 && LiuLiangBean.getLiuliangNum()>tt) {
//                tt=300;
//                if(LiuLiangBean.getLiuliangNum()>300 && LiuLiangBean.getLiuliangNum()>tt) {
//                    tt=400;
//                    if(LiuLiangBean.getLiuliangNum()>400 && LiuLiangBean.getLiuliangNum()>tt) {
//                        tt=500;
//                        if(LiuLiangBean.getLiuliangNum()>500 && LiuLiangBean.getLiuliangNum()>tt) {
//                            tt=600;
//                            if(LiuLiangBean.getLiuliangNum()>600 && LiuLiangBean.getLiuliangNum()>tt) {
//                                tt=700;
//                                if(LiuLiangBean.getLiuliangNum()>700 && LiuLiangBean.getLiuliangNum()>tt) {
//                                    tt=800;
//                                    if(LiuLiangBean.getLiuliangNum()>800 && LiuLiangBean.getLiuliangNum()>tt) {
//                                        tt=900;
//                                        if(LiuLiangBean.getLiuliangNum()>900 && LiuLiangBean.getLiuliangNum()>tt) {
//                                            tt=1000;
//                                            if(LiuLiangBean.getLiuliangNum()>1000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                tt=1500;
//                                                if(LiuLiangBean.getLiuliangNum()>1500 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                    tt=2000;
//                                                    if(LiuLiangBean.getLiuliangNum()>2000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                        tt=3000;
//                                                        if(LiuLiangBean.getLiuliangNum()>3000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                            tt=4000;
//                                                            if(LiuLiangBean.getLiuliangNum()>4000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                tt=5000;
//                                                                if(LiuLiangBean.getLiuliangNum()>5000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                    tt=10000;
//                                                                    if(LiuLiangBean.getLiuliangNum()>10000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                        tt=15000;
//                                                                        if(LiuLiangBean.getLiuliangNum()>15000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                            tt=20000;
//                                                                            if(LiuLiangBean.getLiuliangNum()>20000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                                tt=40000;
//                                                                                if(LiuLiangBean.getLiuliangNum()>40000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                                    tt=60000;
//                                                                                    if(LiuLiangBean.getLiuliangNum()>60000 && LiuLiangBean.getLiuliangNum()>tt) {
//                                                                                        tt=10000;
//                                                                                    }
//                                                                                }
//                                                                            }
//                                                                        }
//                                                                    }
//                                                                }
//                                                            }
//                                                        }
//                                                    }
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//    }
//    if(tt>rr) {
//        rr=tt;
//    }
//
//    TimeSeriesCollection timeseriescollection3 = new TimeSeriesCollection();
//    timeseriescollection3.addSeries(timeseries3);
//    timeseriescollection3.addSeries(timeseries3Tx);
//
////    SimpleDateFormat frm = new SimpleDateFormat("k:mm");
//
//    XYDataset xydataset3 = timeseriescollection3;
//    JFreeChart jfreechart3 = ChartFactory.createTimeSeriesChart("netflux", "time", "flux MB/second", xydataset3, true, true, true);
//    XYPlot xyplot3 = (XYPlot) jfreechart3.getPlot();
//    xyplot3.setBackgroundPaint(Color.black);      //设置背景颜色
//    xyplot3.setDomainGridlinePaint(Color.green);  //设置网格竖线颜色
//    xyplot3.setRangeGridlinePaint(Color.green);   //设置网格横线颜色
//    XYLineAndShapeRenderer xylinerenderer3=(XYLineAndShapeRenderer)xyplot3.getRenderer();
//    xylinerenderer3.setSeriesPaint(0, new Color(0, 255 ,0 ));
//    xylinerenderer3.setSeriesPaint(1, new Color(255, 0 ,0 ));
//
//    DateAxis dateaxis3 = (DateAxis) xyplot3.getDomainAxis();//获取x轴
//    dateaxis3.setDateFormatOverride(new SimpleDateFormat("HH:mm"));
//    dateaxis3.setTickUnit(new DateTickUnit(DateTickUnit.MINUTE, 1));
//
//    // frame1=new ChartPanel(jfreechart,true);
//    dateaxis3.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题
//    dateaxis3.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题
//
//    ValueAxis rangeAxis3=xyplot3.getRangeAxis();//获取y轴
//    rangeAxis3.setRange(0, rr);
////    rangeAxis.setAutoRange(true);
//    rangeAxis3.setLabelFont(new Font("黑体",Font.BOLD,15));
//    jfreechart3.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));
//    jfreechart3.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
//    String filename3 = ServletUtilities.saveChartAsPNG(jfreechart3, 500, 360, null, session);
//    String graphURL3 = request.getContextPath() + "/DisplayChart?filename=" + filename3;

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
            var imgwidth = bodywidth/2.1;
            var imghight = 360*imgwidth/500;
//            document.getElementById("img1").width=imgwidth;
//            document.getElementById("img1").height=imghight
            document.getElementById("img2").width=imgwidth;
            document.getElementById("img2").height=imghight;
            document.getElementById("img3").width=imgwidth;
            document.getElementById("img3").height=imghight;
//            document.getElementById("img4").width=imgwidth;
//            document.getElementById("img4").height=imghight

//            var myiframe = document.createElement("iframe");
//            myiframe.setAttribute("id","img5");
//            myiframe.setAttribute("marginwidth","0");
//            myiframe.setAttribute("marginheight","0");
//            myiframe.setAttribute("frameBorder","0");
//            myiframe.setAttribute("scrolling","no");
//            myiframe.setAttribute("border","0");
//            myiframe.setAttribute("width",imgwidth);
//            myiframe.setAttribute("height",imghight);
//            myiframe.setAttribute("src","myjiframe.jsp");

            document.getElementById("img5").width=imgwidth;
            document.getElementById("img5").height=imghight;
            document.getElementById("img5").setAttribute("src","myjiframe.jsp");
        }
        //        location.href="myjfreezhexian.jsp";
        //        setTimeout("self.location.reload();",1000);
        //        setTimeout("location.href='myjfreezhexian.jsp?flagts=1'",1000);
        setTimeout("document.myform.submit();",60000);
    </script>
</head>

<body onload="setDX()">
<%--<img id="img1" src="<%= graphURL %>" border=0 >--%>
<%--<img id="img4" src="<%= graphURL3 %>"  border=0 >--%>
<iframe id="img5" marginwidth="0" marginheight="0" border=0 frameBorder="0" scrolling="no" ></iframe>
<img id="img2" src="<%= graphURL2 %>"  border=0 >
<img id="img3" src="<%= graphURLMem %>"  border=0 >
<%--<iframe src="myjfreezhexian.jsp" frameBorder="0" width="100%" scrolling="yes" height="100%" ></iframe>--%>
<form name="myform" method="post" action="myjfreezhexian.jsp">
    <input type="hidden" name="flagts" value="1">
</form>
</body>
</html>