package com.hzih.ca.utils.mina;

import org.apache.mina.filter.codec.demux.DemuxingProtocolCodecFactory;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 13-7-26
 * Time: 下午3:23
 * To change this template use File | Settings | File Templates.
 */
public class MessageCodecFactory extends DemuxingProtocolCodecFactory {
    public MessageCodecFactory() {
        super.addMessageDecoder(MessageInfoDecoder.class);
        super.addMessageEncoder(MessageInfo.class, MessageInfoEncoder.class);
    }
}
