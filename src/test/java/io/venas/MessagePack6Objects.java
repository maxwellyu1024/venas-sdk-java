package io.venas;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.UUID;

import org.msgpack.MessagePack;
import org.msgpack.annotation.Message;
import org.msgpack.packer.Packer;
import org.msgpack.unpacker.Unpacker;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class MessagePack6Objects {

    /**
     * MessageData Message Objects
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
        MessageData src1 = new MessageData();
        src1.uuid = uuid;
        src1.name = "MessagePack6-src1";
        src1.version = 0.6;

        MessageData src2 = new MessageData();
        src2.uuid = uuid;
        src2.name = "MessagePack6-src2";
        src2.version = 10.6;

        MessageData src3 = new MessageData();
        src3.uuid = uuid;
        src3.name = "MessagePack6-src3";
        src3.version = 1.6;

        try {
            MessagePack msgPack = new MessagePack();

            // Serialization
            log.debug("------ Serialization ------");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Packer packer = msgPack.createPacker(out);
            packer.write(src1);
            packer.write(src2);
            packer.write(src3);

            byte[] bytes = out.toByteArray();
            log.debug("Bytes Array Length: [{}]", bytes.length);

            // Deserialization
            log.debug("------ Deserialization ------");
            ByteArrayInputStream in = new ByteArrayInputStream(bytes);
            Unpacker unpacker = msgPack.createUnpacker(in);

            MessageData dst1 = unpacker.read(MessageData.class);
            MessageData dst2 = unpacker.read(MessageData.class);
            MessageData dst3 = unpacker.read(MessageData.class);

            log.debug("Check Object for UUID: [{}]", dst1.uuid);

            System.out.println(uuid);
			System.out.println(dst1.uuid);
			System.out.println(uuid.equals(dst1.uuid));
        } catch (Exception ex) {
            log.error("MessagePack Serialization And Deserialization error", ex);
        }
    }
}