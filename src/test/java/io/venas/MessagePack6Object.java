package io.venas;

import java.util.UUID;

import org.apache.commons.codec.binary.Hex;
import org.msgpack.MessagePack;
import org.msgpack.annotation.Message;
import org.msgpack.type.Value;

import com.alibaba.fastjson.JSON;

import io.venas.data.SmartContract;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MessagePack6Object {

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
			System.out.println(Hex.encodeHexString(bytes));

			// Deserialization
			log.debug("------ Deserialization ------");
			MessageData dst = msgPack.read(bytes, MessageData.class);
			log.debug("Check Object for UUID: [{}]", dst.uuid);
			System.out.println(uuid);
			System.out.println(dst.uuid);
			System.out.println(uuid.equals(dst.uuid));

			Value value = msgPack.read(bytes);

			System.out.println(value);
			System.out.println(getPrintHex(bytes));
			String str = "134,166,72,101,97,100,101,114,135,162,73,68,205,20,116,164,84,105,109,101,206,94,14,225,245,171,69,99,111,115,121,115,116,101,109,73,68,1,165,75,101,121,73,68,207,15,24,88,100,62,248,159,117,169,78,101,116,119,111,114,107,73,68,0,169,80,117,98,108,105,99,75,101,121,196,64,87,156,250,60,61,249,156,41,7,105,62,81,174,68,79,150,211,79,246,237,155,87,9,96,91,53,79,65,214,38,238,168,251,157,29,106,203,157,97,33,78,180,150,174,209,236,138,98,89,101,203,20,118,157,235,222,125,66,158,17,166,191,101,58,170,80,114,105,118,97,116,101,70,111,114,192,174,84,111,107,101,110,69,99,111,115,121,115,116,101,109,0,166,77,97,120,83,117,109,160,167,80,97,121,79,118,101,114,160,168,83,105,103,110,101,100,66,121,0,166,80,97,114,97,109,115,130,172,100,97,116,97,95,99,111,110,116,101,110,116,163,97,115,100,164,116,105,109,101,165,50,49,52,51,50";
			byte[] bbb = to16(str,10);
			System.out.println(getPrintHex(bbb));
			Value value2 = msgPack.read(bbb);
			System.out.println("value2"+value2);
			MessagePack msgPack2 = new MessagePack();
			
//			  TemplateRegistry registry = new TemplateRegistry(null);
//		        ReflectionTemplateBuilder builder = new ReflectionTemplateBuilder(registry);
//		        Template<SmartContract> objTemplate = builder.buildTemplate(SmartContract.class);
//		        BufferUnpacker unpacker = msgPack2.createBufferUnpacker();
//		        unpacker.resetReadByteCount();
//		        unpacker.wrap(bbb);
//		        SmartContract value3 =    objTemplate.read(unpacker, null);
//		        
		        
//			SmartContract value3 = msgPack2.read(bbb,SmartContract.class);
//			System.out.println(JSON.toJSONString(value3));
		} catch (Exception ex) {
			log.error("MessagePack Serialization And Deserialization error", ex);
		}
	}

	public static String getPrintHex(byte[] data, int offset, int limit) {
		StringBuffer sb = new StringBuffer();
		for (int i = offset; i < offset + limit; i++) {
			sb.append(String.format("%02x", data[i]));
			sb.append(",");
		}
		return sb.toString();
	}

	public static String getPrintHex(byte[] data) {

		return getPrintHex(data, 0, data.length);
	}

	public static byte[] to16(String str,int radix) {
		String[] bs = str.split(",");
		byte[] buf = new byte[bs.length];
		for (int i = 0; i < bs.length; i++) {
			buf[i] = (byte) (Integer.parseInt(bs[i], radix) & 0xff);
		}
		return buf;
	}
}