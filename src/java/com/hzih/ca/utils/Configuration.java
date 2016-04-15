package com.hzih.ca.utils;

import com.hzih.ca.entity.ApplyRequest;
import com.hzih.ca.entity.DownRequest;
import com.hzih.ca.entity.FaceInfoRequest;
import com.hzih.ca.entity.SipType;
import com.inetec.common.exception.Ex;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import java.io.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

public class Configuration {
    static Logger logger = Logger.getLogger(Configuration.class);

    private Document document;
    public String confPath;

    public Configuration(Document doc) {
        this.document = doc;
    }

    public Configuration(byte[] buff) {
        SAXReader saxReader = new SAXReader();
        try {
            InputStream is = byteToString(buff);
            document = saxReader.read(is);
        } catch (DocumentException e) {
            logger.info(e.getMessage(),e);
        }
    }

    private InputStream byteToString(byte[] buff) {
        return new ByteArrayInputStream(buff);
    }

    public boolean getPrivated() {
        String value = "1";
        Element channel = (Element)document.selectSingleNode("/configuration/system/ichange/stp/channel[@value='"+value+"']");
        return Boolean.valueOf(channel.element("privated").getText());
    }

    public Configuration(String path) throws Ex {
        this.confPath = path;
        SAXReader saxReader = new SAXReader();
        try {
            document = saxReader.read(path);
        } catch (DocumentException e) {
            e.printStackTrace();
            logger.info(e.getMessage(),e);
        }
    }

    public Configuration(InputStream is, String path) throws Ex {
        this.confPath = path;
        SAXReader saxReader = new SAXReader();
        try {
            document = saxReader.read(is);
        } catch (DocumentException e) {
            logger.info(e.getMessage(),e);
        }
    }


    public FaceInfoRequest getFaceInfoRequest() throws ParseException {
        Element base = (Element)document.selectSingleNode("/Query");
        if(base!=null){
            FaceInfoRequest faceInfo = new FaceInfoRequest();
            String deviceType = base.element("DeviceType").getText().trim();
            String deviceId = base.element("DeviceID").getText().trim();
            String taskId = base.element("TaskID").getText().trim();
            String cmdType = base.element("CmdType").getText().trim();
            String latitude = base.element("Latitude").getText().trim();
            String longitude = base.element("Longitude").getText().trim();
            String dateTime = base.element("DateTime").getText().trim();
            String faceNum = base.element("FaceNum").getText().trim();
            String compStatus = base.element("CompStatus").getText().trim();
            String compressFormat = base.element("CompressFormat").getText().trim();
            String fileName = base.element("FileName").getText().trim();
            String fileSize = base.element("FileSize").getText().trim();
            faceInfo.setDeviceType(deviceType);
            faceInfo.setDeviceId(deviceId);
            faceInfo.setTaskId(taskId);
            faceInfo.setCmdType(cmdType);
            faceInfo.setLatitude(Double.parseDouble(latitude));
            faceInfo.setLongitude(Double.parseDouble(longitude));
            faceInfo.setDateTime(DateUtils.parse(dateTime,DateUtils.format));
            faceInfo.setFaceNum(Integer.parseInt(faceNum.substring(2),16));
            faceInfo.setCompStatus(compStatus);
            faceInfo.setCompressFormat(compressFormat);
            faceInfo.setFileName(fileName);
            faceInfo.setFileSize(Long.parseLong(fileSize.substring(2),16));
            return faceInfo;
        }
        return null;
    }


    public DownRequest getDownConfigRequest() {
        Element base = (Element)document.selectSingleNode("/Down");
        if(base!=null){
            DownRequest downConfig = new DownRequest();
            downConfig.setDeviceId(base.element("DeviceID").getText().trim());
            downConfig.setDeviceType(base.element("DeviceType").getText().trim());
            downConfig.setCmdType(base.element("CmdType").getText().trim());
            try{
                downConfig.setOsType(base.element("OSType").getText().trim());
            } catch (Exception e){
                downConfig.setOsType(SipType.Win);
            }

            return downConfig;
        }
        return null;
    }

    public ApplyRequest getApplyRequest() {
        Element base = (Element)document.selectSingleNode("/Apply");
        if(base!=null){
            ApplyRequest applyRequest = new ApplyRequest();
            applyRequest.setDeviceId(base.element("DeviceID").getText().trim());
            applyRequest.setDeviceType(base.element("DeviceType").getText().trim());
            applyRequest.setCmdType(base.element("CmdType").getText().trim());
            try {
                applyRequest.setProvince(new String(Base64.decodeBase64((base.element("Province").getTextTrim().getBytes())),"gbk"));
                applyRequest.setCity(new String(Base64.decodeBase64((base.element("City").getTextTrim().getBytes())),"gbk"));
                applyRequest.setOrganization(new String(Base64.decodeBase64((base.element("Organization").getTextTrim().getBytes())),"gbk"));
                applyRequest.setInstitution(new String(Base64.decodeBase64((base.element("Institution").getTextTrim().getBytes())),"gbk"));
                applyRequest.setPlace(new String(Base64.decodeBase64((base.element("Place").getTextTrim().getBytes())),"gbk"));
                applyRequest.setAddress(new String(Base64.decodeBase64((base.element("Address").getTextTrim().getBytes())), "gbk"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return applyRequest;
        }
        return null;
    }

    public String editConnectorIp(String ip, String port) {
        try{
            Element connector = (Element) document.selectSingleNode("/Server/Service/Connector[@port=" + port + "]");
            if(connector != null){
                connector.attribute("address").setText(ip);
                String result = save();
                if(result.equals("保存成功")){
                    if(port.equals(""+8443)){
                        return "更新管理服务接口设定IP地址成功";
                    }else if(port.equals(""+8000)){
                        return "更新集控采集数据接口设定IP地址成功";
                    }else{
                        return "更新成功,端口是"+port;
                    }
                }else{
                    return result;
                }
            }
        } catch (Exception e){
            logger.info(e.getMessage(),e);
        }
        return "更新出错";
    }

    public String getConnectorIp(String port) {
        String ip = "";
        try{
           Element connector = (Element) document.selectSingleNode("/Server/Service/Connector[@port=" + port + "]");
            if(connector != null){
                ip = connector.attribute("address").getText();
            }
        } catch (Exception e){
            logger.info(e.getMessage(),e);
        }
        return ip;
    }

    public List<String> getAllowIPs(){
        List<String> allowIps = new ArrayList<String>();
        try{
            Element valve = (Element) document.selectSingleNode("/Server/Service/Engine/Valve");
            if(valve!=null){
                String ip = valve.attribute("allow").getText();
                String[] ips = ip.split("\\|");
                if(ips.length>1){
                    for (int i = 0; i < ips.length; i ++){
                        allowIps.add(ips[i]);
                    }
                }else{
                    allowIps.add(ip);
                }
            }
        } catch (Exception e){
            logger.info(e.getMessage(),e);
        }
        return allowIps;
    }

    public String editAllowIp(String ip) {
        try{
            Element value = (Element) document.selectSingleNode("/Server/Service/Engine/Valve");
            if(value!=null){
                ip = value.attribute("allow").getText() + ip;
                value.attribute("allow").setText(ip);
                String result = save();
                if(result.equals("保存成功")){
                        return "更新管理客户机地址成功";
                }else{
                    return result;
                }
            }
        } catch (Exception e){
            logger.info(e.getMessage(),e);
        }
        return "更新出错";
    }
    public String deleteAllowIp(String ip) {
        try{
            Element value = (Element) document.selectSingleNode("/Server/Service/Engine/Valve");
            if(value!=null){
                value.attribute("allow").setText(ip);
                String result = save();
                if(result.equals("保存成功")){
                        return "删除管理客户机地址成功";
                }else{
                    return result;
                }
            }
        } catch (Exception e){
            logger.info(e.getMessage(),e);
        }
        return "删除出错";
    }

    public String save() {
        String result = null;
        XMLWriter output = null;
        try {
            File file = new File(confPath);
            FileInputStream fin = new FileInputStream(file);
            byte[] bytes = new byte[fin.available()];
            while (fin.read(bytes) < 0) fin.close();
            OutputFormat format = OutputFormat.createPrettyPrint();
            format.setEncoding("UTF-8");
            output = new XMLWriter(new FileOutputStream(file),format);
            if(document != null){
                output.write(document);
                return result = "保存成功";
            }else{
                result = "dom4j处理出错";
            }
        } catch (FileNotFoundException e) {
            logger.error(e.getMessage(),e);
            result = e.getMessage();
        } catch (IOException e) {
            logger.error(e.getMessage(),e);
            result = e.getMessage();
        } finally {
            try {
                if (output != null)
                    output.close();
            } catch (IOException e) {
                logger.error(e.getMessage(),e);
                result = e.getMessage();
            }
        }
        return "保存失败,"+result;
    }


}