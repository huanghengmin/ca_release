package com.hzih.ca.utils.mina;

import com.hzih.ca.entity.FaceInfoRequest;
import com.hzih.ca.entity.SipType;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;
import org.apache.mina.filter.codec.demux.MessageEncoder;

import java.io.FileOutputStream;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 13-7-26
 * Time: 下午2:33
 * To change this template use File | Settings | File Templates.
 */
public class MessageInfoEncoder implements MessageEncoder {
    @Override
    public void encode(IoSession ioSession, Object message, ProtocolEncoderOutput out) throws Exception {
        //To change body of implemented methods use File | Settings | File Templates.
        if(message instanceof MessageInfo){
            MessageInfo messageInfo = (MessageInfo) message;
//            IoBuffer buffer = IoBuffer.allocate(messageInfo.getBodyLen() + 28);
            FaceInfoRequest f = messageInfo.getFaceInfoRequest();
            IoBuffer buffer;
            if(f!=null){
                buffer = IoBuffer.allocate(28 + messageInfo.getBodyLen() + (int) f.getFileSize());
            } else {
                buffer = IoBuffer.allocate(28 + messageInfo.getBodyLen() );
            }
            buffer.setAutoExpand(true);
            buffer.put(MessageInfo.L);
            buffer.put(MessageInfo.Z);
            buffer.put(messageInfo.getVersion());
            buffer.putInt(messageInfo.getBodyLen());
            buffer.put(messageInfo.getReserved());
            buffer.put(messageInfo.getBody());
            if(f!=null){
                buffer.put(f.getFileBuff());
            }
            buffer.flip();


//            testDecode(buffer,ioSession);
//            buffer.flip();



            out.write(buffer);
            out.flush();


        }
    }

    private void testDecode(IoBuffer buffer, IoSession ioSession) throws Exception{
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
            String xmlStr = new String(body, messageInfo.getCharset());
            String cmdType;
            if(xmlStr.indexOf("<Response>") > -1 ){
                cmdType = null;
            } else {
                cmdType = xmlStr.substring(xmlStr.indexOf("<CmdType>")+9,xmlStr.indexOf("</CmdType>")).trim();
            }
            if(SipType.FaceInfo.equalsIgnoreCase(cmdType)){
                String fileName = xmlStr.substring(xmlStr.indexOf("<FileName>")+10,xmlStr.indexOf("</FileName>")).trim();
                int fileSize = Integer.parseInt(xmlStr.substring(xmlStr.indexOf("<FileSize>") + 10, xmlStr.indexOf("</FileSize>")).trim());
                Context context = (Context) ioSession.getAttribute(CONTEXT);
                if(context == null){
                    context = new Context();
                    context.strLength = fileName.getBytes(messageInfo.getCharset()).length;
                    context.byteStr = new byte[context.strLength];
                    context.fileSize = fileSize;
                    context.byteFile = new byte[context.fileSize];
                    ioSession.setAttribute(CONTEXT, context);
                }
                FaceInfoRequest f = new FaceInfoRequest();
                f.setCmdType(cmdType);
                f.setFileName(fileName);
                byte[] byteFile = context.byteFile;
                int count = context.count;
                while (buffer.hasRemaining()){
                    byte b = buffer.get();
                    if(count != -1){
                        byteFile[count] = b;
                    }
                    count++;
                }
                context.count = count;
                ioSession.setAttribute(CONTEXT, context);
                System.out.println(" "+context.count +" == "+ context.fileSize);
                if(context.count == context.fileSize){
                    f.setFileBuff(context.byteFile);
                    f.setFileName(fileName);
                    messageInfo.setFaceInfoRequest(f);
                    context.reset();
                } else {
                    f.setFileBuff(context.byteFile);
                    f.setFileName(fileName);
                    messageInfo.setFaceInfoRequest(f);
                    context.reset();
                }
                FileOutputStream os = new FileOutputStream("D:/test/xx.exe");
                os.write(f.getFileBuff());
                os.close();
            }

        }
    }

    private AttributeKey CONTEXT = new AttributeKey(getClass(), "context");

    private class Context{
        public int dataType;
        public byte[] byteFile;
        public int count;
        public int strLength;
        public boolean isReadName;
        public int fileSize;
        public byte[] byteStr;
        public String fileName;
        public boolean init = false;

        public void reset(){
            dataType = 0;
            byteFile = null;
            count = 0;
            strLength = 0;
            isReadName = false;
            fileSize = 0;
            byteStr = null;
            fileName = null;

        }
    }


}
