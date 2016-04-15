package com.hzih.ca.utils.mina;


import com.hzih.ca.entity.FaceInfoRequest;

import java.io.Serializable;

/**
 * Created with IntelliJ IDEA.
 * User: sunny
 * Date: 14-7-25
 * Time: 上午11:17
 */
public class MessageInfo implements Serializable{

    private static final long serialVersionUID = 1L;
    public static final byte L = 0x4C;
    public static final byte Z = 0x5A;
    public static final byte Version = 0x01;
    private String charset = "gbk";
    public static final int CmdTypeLen = 120;


    private byte version;//1 byte 0x01
    private int bodyLen;//4 byte
    private byte[] reserved;//21 byte
    private byte[] body;
    private FaceInfoRequest faceInfoRequest;
    private String cmdType;

    public MessageInfo() {
    }

    public byte getVersion() {
        return version;
    }

    public void setVersion(byte version) {
        this.version = version;
    }

    public int getBodyLen() {
        return bodyLen;
    }

    public void setBodyLen(int bodyLen) {
        this.bodyLen = bodyLen;
    }

    public byte[] getReserved() {
        return reserved;
    }

    public void setReserved(byte[] reserved) {
        this.reserved = reserved;
    }

    public byte[] getBody() {
        return body;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public String getCharset() {
        return charset;
    }

    public void setCharset(String charset) {
        this.charset = charset;
    }

    public FaceInfoRequest getFaceInfoRequest() {
        return faceInfoRequest;
    }

    public void setFaceInfoRequest(FaceInfoRequest faceInfoRequest) {
        this.faceInfoRequest = faceInfoRequest;
    }


    public void setCmdType(String cmdType) {
        this.cmdType = cmdType;
    }

    public String getCmdType() {
        return cmdType;
    }
}
