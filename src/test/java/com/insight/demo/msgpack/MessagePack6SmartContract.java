package com.insight.demo.msgpack;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.msgpack.MessagePack;
import org.msgpack.annotation.Message;
import org.msgpack.type.Value;

import io.venas.data.SmartContract;
import io.venas.data.SmartContract.Header;
import lombok.extern.slf4j.Slf4j;


/**
 * MessagePack6Objects
 *
 * @author yhu
 */
@Slf4j
public class MessagePack6SmartContract {

 

    /**
     * Test MessagePack6Objects
     */

    public static void main(String[] args) {
        log.debug("MessagePack6Objects for Objects");

        String uuid = UUID.randomUUID().toString();

        // INIT OBJ
        SmartContract src = new SmartContract();
        Header Header=new Header();
        Header.setEcosystemID(1L);
        Header.setID(12);
        Header.setKeyID(123L);
        Header.setNetworkID(14L);
        Header.setPrivateFor(new String[]{"msg", "pack", "for", "java"});
        Header.setPublicKey(new byte[]{0x30, 0x31, 0x32});
        Header.setTime(System.currentTimeMillis());
        
		src.setHeader(Header);
        src.setMaxSum("MaxSum");
        Map<String, String> Params=new HashMap<String, String>();
        Params.put("key", "value");
		src.setParams(Params);
        src.setPayOver("PayOver");
        src.setSignedBy(1L);
        src.setTokenEcosystem(1L);
        try {
            MessagePack msgPack = new MessagePack();

            // Serialization
            log.debug("------ Serialization ------");
            byte[] bytes = msgPack.write(src);
            log.debug("Bytes Array Length: [{}]", bytes.length);
            System.out.println(io.venas.MessagePack6Object.getPrintHex(bytes));
            // Deserialization
            log.debug("------ Deserialization ------");
            SmartContract dst = msgPack.read(bytes, SmartContract.class);
            log.debug("Check Object for UUID: [{}]", dst.getMaxSum());

//            assertEquals(uuid, dst.uuid);

//            System.out.println(uuid.equals(dst.uuid));
            
            Value value2 = msgPack.read(bytes);
			System.out.println(value2);
        } catch (Exception ex) {
            log.error("MessagePack Serialization And Deserialization error", ex);
        }
    }
}
