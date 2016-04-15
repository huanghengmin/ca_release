package com.hzih.ca.utils.mina;

import com.hzih.ca.entity.FaceInfoRequest;
import com.hzih.ca.entity.SipType;
import org.apache.log4j.Logger;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.apache.mina.filter.codec.demux.MessageDecoder;
import org.apache.mina.filter.codec.demux.MessageDecoderResult;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 13-7-26
 * Time: 下午2:33
 * To change this template use File | Settings | File Templates.
 */
public class MessageInfoDecoder implements MessageDecoder {

    final Logger logger = Logger.getLogger(getClass());

    private AttributeKey CONTEXT = new AttributeKey(getClass(), "context");

    @Override
    public MessageDecoderResult decodable(IoSession session, IoBuffer buffer) {
        Context context = (Context) session.getAttribute(CONTEXT);
        if(context!=null && context.init){
            return MessageDecoderResult.OK;
        }

        int len = buffer.remaining();//当前接收的消息总长度
        if(len<28){
             return MessageDecoderResult.NEED_DATA;
        } else { //消息头28长度
            byte L = buffer.get();
            byte Z = buffer.get();
            byte version = buffer.get();
            int bodyLen = buffer.getInt();
            byte[] reserved = new byte[21];
            buffer.get(reserved);

            int realMessageLen = bodyLen + 28;//可解包的长度
            if(len >= realMessageLen) {
                if (L == MessageInfo.L && Z == MessageInfo.Z) {
                    return MessageDecoderResult.OK;
                } else {
                    return MessageDecoderResult.NOT_OK;
                }
            } else {
                return MessageDecoderResult.NEED_DATA;
            }
        }
    }

    @Override
    public MessageDecoderResult decode(IoSession ioSession, IoBuffer buffer, ProtocolDecoderOutput out) throws Exception {
        Context context = (Context) ioSession.getAttribute(CONTEXT);
        if(context!=null && context.init){
            byte[] byteFile = context.byteFile;
            int count = context.count;
            while(buffer.hasRemaining()){
                byte b = buffer.get();
                if(count != -1){
                    byteFile[count] = b;
                }
                count++;
            }
            context.count = count;
            ioSession.setAttribute(CONTEXT, context);
//            System.out.println(" " + context.count + " == " + context.fileSize);
            if(context.count==context.fileSize){
                MessageInfo messageInfo = new MessageInfo();
                FaceInfoRequest f = new FaceInfoRequest();
                f.setCmdType(context.cmdType);
                f.setFileName(context.fileName);
                f.setFileBuff(context.byteFile);
                messageInfo.setFaceInfoRequest(f);
                messageInfo.setVersion(context.version);
                messageInfo.setBodyLen(context.bodyLen);
                messageInfo.setReserved(context.reserved);
                messageInfo.setBody(context.body);
                messageInfo.setCharset(context.charset);

                messageInfo.setCmdType(context.cmdType);
                out.write(messageInfo);
                context.reset();
                ioSession.setAttribute(CONTEXT, context);
                buffer.free();
                return MessageDecoderResult.OK;
            } else {
                return MessageDecoderResult.NEED_DATA;
            }
        }

        byte L = buffer.get();
        byte Z = buffer.get();
        if (L == MessageInfo.L && Z == MessageInfo.Z) {
            MessageInfo messageInfo = new MessageInfo();
            byte version = buffer.get();
            int bodyLen = buffer.getInt();
            byte[] reserved = new byte[21];
            buffer.get(reserved);
            byte[] body = new byte[bodyLen];
            buffer.get(body);
            messageInfo.setVersion(version);
            messageInfo.setBodyLen(bodyLen);
            messageInfo.setReserved(reserved);
            messageInfo.setBody(body);
            String xmlStr = new String(body, messageInfo.getCharset());
            String cmdType;
            if(xmlStr.indexOf("<Response>") > -1 ){
                cmdType = null;
            } else {
                if(xmlStr.startsWith("<?xml version=")){
                    cmdType = xmlStr.substring(xmlStr.indexOf("<CmdType>")+9,xmlStr.indexOf("</CmdType>")).trim();
                } else {
                    cmdType = null;
                }
                messageInfo.setCmdType(cmdType);
            }
            if(SipType.FaceInfo.equalsIgnoreCase(cmdType)){
                String fileName = xmlStr.substring(xmlStr.indexOf("<FileName>")+10,xmlStr.indexOf("</FileName>")).trim();
                int fileSize = Integer.parseInt(
                        xmlStr.substring(xmlStr.indexOf("<FileSize>") + 10,
                                         xmlStr.indexOf("</FileSize>")).trim().
                                substring(2),16);
                context = (Context) ioSession.getAttribute(CONTEXT);

                if(context == null){
                    context = new Context();
                }
                context.fileSize = fileSize;
                context.byteFile = new byte[context.fileSize];
                context.init = true;
                context.fileName = fileName;
                context.body = body;
                context.reserved = reserved;
                context.version = version;
                context.cmdType = cmdType;
                context.charset = messageInfo.getCharset();
                ioSession.setAttribute(CONTEXT, context);

                byte[] byteFile = context.byteFile;
                int count = context.count;
                while(buffer.hasRemaining()){
                    byte b = buffer.get();
                    if(count != -1){
                        byteFile[count] = b;
                    }
                    count++;
                }
                context.count = count;
                ioSession.setAttribute(CONTEXT, context);
                if(context.count==context.fileSize){
                    System.out.println(" " + context.count + " == " + context.fileSize);
                    FaceInfoRequest f = new FaceInfoRequest();
                    f.setCmdType(cmdType);
                    f.setFileName(fileName);
                    f.setFileBuff(context.byteFile);
                    messageInfo.setFaceInfoRequest(f);
                    out.write(messageInfo);
                    context.reset();
                    ioSession.setAttribute(CONTEXT, context);
                } else {
                    return MessageDecoderResult.NEED_DATA;
                }

            } else {
                out.write(messageInfo);
            }
        } else {
            System.out.println("==============");
        }
        buffer.free();
        return MessageDecoderResult.OK;
    }

    @Override
    public void finishDecode(IoSession ioSession, ProtocolDecoderOutput protocolDecoderOutput) throws Exception {

    }

    private class Context{
        public int dataType;
        public byte[] byteFile;
        public int count;
        public int fileSize;
        public boolean init = false;
        public String fileName;
        public byte version;//1 byte 0x01
        public int bodyLen;//4 byte
        public byte[] reserved;//21 byte
        public byte[] body;
        public String charset;
        public String cmdType;

        public void reset(){
            dataType = 0;
            byteFile = null;
            fileName = null;
            count = 0;
            fileSize = 0;
            version = 0;
            bodyLen = 0;
            reserved = null;
            body = null;
            charset = null;
            cmdType = null;
        }
    }

}
