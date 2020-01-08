package com.insight.demo.msgpack;

import static org.msgpack.template.Templates.TString;
import static org.msgpack.template.Templates.tList;

import java.util.ArrayList;
import java.util.List;

import org.msgpack.MessagePack;
import org.msgpack.type.Value;
import org.msgpack.unpacker.Converter;

import lombok.extern.slf4j.Slf4j;

/**
 * MessagePack6Objects
 *
 * @author yhu
 */
@Slf4j
public class MessagePack6DynamicTyping {


    /**
     * Test MessagePack6Objects
     */
    public static void main(String[] args) {
        log.debug("MessagePack6Objects for Objects");

        // Create serialize objects.
        List<String> src = new ArrayList<String>();
        src.add("msgpack");
        src.add("kumofs");
        src.add("viver");

        MessagePack msgpack = new MessagePack();

        try {

            // Serialize
            byte[] raw = msgpack.write(src);

            // Deserialize directly using a template
            List<String> dst1 = msgpack.read(raw, tList(TString));

            // Or, Deserialze to Value then convert type.
            Value dynamic = msgpack.read(raw);
            List<String> dst2 = new Converter(dynamic).read(tList(TString));

        } catch (Exception ex) {
            log.error("MessagePack Serialization And Deserialization error", ex);
        }
    }
}
