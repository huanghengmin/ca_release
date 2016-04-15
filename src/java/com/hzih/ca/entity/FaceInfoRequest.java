package com.hzih.ca.entity;



import com.hzih.ca.utils.Configuration;
import com.hzih.ca.utils.DateUtils;

import java.text.ParseException;
import java.util.Date;

/**
 * Created by Administrator on 15-7-24.
 */
public class FaceInfoRequest extends SipXml {

    private long id;
    private double latitude;
    private double longitude;
    private String taskId;
    private Date dateTime;
    private int faceNum;
    private String compStatus;
    private String compressFormat;
    private String fileName;
    private String filePathA;
    private String filePathH;
    private String filePathHead;
    private long fileSize;
    private byte[] fileBuff;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }

    public double getLatitude() {
        return latitude;
    }

    public void setLatitude(double latitude) {
        this.latitude = latitude;
    }

    public double getLongitude() {
        return longitude;
    }

    public void setLongitude(double longitude) {
        this.longitude = longitude;
    }

    public Date getDateTime() {
        return dateTime;
    }

    public void setDateTime(Date dateTime) {
        this.dateTime = dateTime;
    }

    public int getFaceNum() {
        return faceNum;
    }

    public void setFaceNum(int faceNum) {
        this.faceNum = faceNum;
    }

    public String getCompStatus() {
        return compStatus;
    }

    public void setCompStatus(String compStatus) {
        this.compStatus = compStatus;
    }

    public String getCompressFormat() {
        return compressFormat;
    }

    public void setCompressFormat(String compressFormat) {
        this.compressFormat = compressFormat;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFilePathA() {
        return filePathA;
    }

    public void setFilePathA(String filePathA) {
        this.filePathA = filePathA;
    }

    public String getFilePathH() {
        return filePathH;
    }

    public void setFilePathH(String filePathH) {
        this.filePathH = filePathH;
    }

    public String getFilePathHead() {
        return filePathHead;
    }

    public void setFilePathHead(String filePathHead) {
        this.filePathHead = filePathHead;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public byte[] getFileBuff() {
        return fileBuff;
    }

    public void setFileBuff(byte[] fileBuff) {
        this.fileBuff = fileBuff;
    }

    public FaceInfoRequest xmlToBean(byte[] buff) throws ParseException {
        Configuration config = new Configuration(buff);
        FaceInfoRequest faceInfo = config.getFaceInfoRequest();
        return faceInfo;
    }

    @Override
    public String toString() {
        return "<?xml version=\"1.0\"?>\r\n\r\n" +
                "<Query>\r\n" +
                "<DeviceType>" + deviceType + "</DeviceType>\r\n" +
                "<DeviceID>" + deviceId + "</DeviceID>\r\n" +
                "<CmdType>" + SipType.FaceInfo + "</CmdType>\r\n" +
                "<TaskID>" + taskId + "</TaskID>\r\n" +
                "<Latitude>" + latitude + "</Latitude>\r\n" +
                "<Longitude>" + longitude + "</Longitude>\r\n" +
                "<DateTime>" + DateUtils.formatDate(dateTime, DateUtils.format) + "</DateTime>\r\n" +
                "<FaceNum>0x" + Integer.toHexString(faceNum) + "</FaceNum>\r\n" +
                "<CompStatus>" + compStatus + "</CompStatus>\r\n" +
                "<CompressFormat>" + compressFormat + "</CompressFormat>\r\n" +
                "<FileName>" + fileName + "</FileName>\r\n" +
                "<FileSize>0x" + Long.toHexString(fileSize) + "</FileSize>\r\n" +
                "</Query>";
    }
}
