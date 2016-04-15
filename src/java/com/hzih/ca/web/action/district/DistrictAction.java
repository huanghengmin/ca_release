package com.hzih.ca.web.action.district;

import cn.collin.commons.domain.PageResult;
import com.hzih.ca.domain.District;
import com.hzih.ca.service.DistrictService;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.List;

public class DistrictAction extends ActionSupport {
    private static Logger logger = Logger.getLogger(DistrictAction.class);
    private DistrictService districtService;
    private int start;
    private int limit;

    public int getStart() {
        return start;
    }

    public void setStart(int start) {
        this.start = start;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    public static Logger getLogger() {
        return logger;
    }

    public static void setLogger(Logger logger) {
        DistrictAction.logger = logger;
    }

    public DistrictService getDistrictService() {
        return districtService;
    }

    public void setDistrictService(DistrictService districtService) {
        this.districtService = districtService;
    }

    public String findCity()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String parentId = request.getParameter("parentId");
        String json = null;
        try {
            PageResult pageResult =  districtService.findCity(Long.parseLong(parentId),start,limit);
            if(pageResult!=null){
                List<District> districts  = pageResult.getResults();
                int count =  pageResult.getAllResultsAmount();
                if(districts!=null){
                    json = getCityJson(districts,count);
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
        }
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }
    
    public String findProvince()throws Exception{
        HttpServletRequest request = ServletActionContext.getRequest();
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String json = null;
        try {
            PageResult pageResult =  districtService.findProvince(start,limit);
            if(pageResult!=null){
                List<District> districts  = pageResult.getResults();
                int count =  pageResult.getAllResultsAmount();
                if(districts!=null){
                    json = getProvinceJson(districts,count);
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
        }
        writer.write(json);
        writer.flush();
        writer.close();
        return null;
    }

    private String getProvinceJson(List<District> districts, int count) {
        StringBuilder json = new StringBuilder("{totalCount:"+count+",root:[");
        Iterator<District> iterator = districts.iterator();
        while (iterator.hasNext()){
            District district = iterator.next();
            if(iterator.hasNext()){
                json.append("{");
                json.append("id:'"+district.getId()+"',");
                json.append("districtName:'"+district.getDistrictName()+"'");
                json.append("},");
            }else {
                json.append("{");
                json.append("id:'"+district.getId()+"',");
                json.append("districtName:'"+district.getDistrictName()+"'");
                json.append("}");
            }
        }
        json.append("]}");
        return json.toString();
    }


    private String getCityJson(List<District> districts, int count) {
        StringBuilder json = new StringBuilder("{totalCount:"+count+",root:[");
        Iterator<District> iterator = districts.iterator();
        while (iterator.hasNext()){
            District district = iterator.next();
            if(iterator.hasNext()){
                json.append("{");
                json.append("id:'"+district.getId()+"',");
                json.append("districtName:'"+district.getDistrictName()+"'");
                json.append("},");
            }else {
                json.append("{");
                json.append("id:'"+district.getId()+"',");
                json.append("districtName:'"+district.getDistrictName()+"'");
                json.append("}");
            }
        }
        json.append("]}");
        return json.toString();
    }
}
