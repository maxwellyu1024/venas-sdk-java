package com.insight.demo.msgpack;

import java.util.UUID;

import org.msgpack.MessagePack;
import org.msgpack.annotation.Message;
import org.msgpack.type.Value;

import lombok.extern.slf4j.Slf4j;


/**
 * MessagePack6Objects
 *
 * @author yhu
 */
@Slf4j
public class MessagePack6Object {

    /**
     * MessageData Message Object
     */
    @Message // Annotation
    public static class MessageData {
        // public fields are serialized.
        public String uuid;
        public String name;
        public double version;
    }


    /**
     * Test MessagePack6Objects
     */

    public static void main(String[] args) {
        log.debug("MessagePack6Objects for Objects");

        String uuid = UUID.randomUUID().toString();

        // INIT OBJ
        MessageData src = new MessageData();
        src.uuid = uuid;
        src.name = "MessagePack6";
        src.version = 0.6;

        try {
            MessagePack msgPack = new MessagePack();

            // Serialization
            log.debug("------ Serialization ------");
            byte[] bytes = msgPack.write(src);
            log.debug("Bytes Array Length: [{}]", bytes.length);

            // Deserialization
            log.debug("------ Deserialization ------");
            MessageData dst = msgPack.read(bytes, MessageData.class);
            log.debug("Check Object for UUID: [{}]", dst.uuid);

//            assertEquals(uuid, dst.uuid);

            System.out.println(uuid.equals(dst.uuid));
            
            Value value2 = msgPack.read(bytes);
			System.out.println(value2);
        } catch (Exception ex) {
            log.error("MessagePack Serialization And Deserialization error", ex);
        }
    }
}
