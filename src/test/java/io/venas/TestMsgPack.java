package io.venas;

//import org.assertj.core.util.Maps;
import org.msgpack.MessagePack;
import org.msgpack.template.Templates;
import org.msgpack.type.Value;
import org.msgpack.unpacker.Converter;

import com.google.common.collect.Maps;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by wangdi on 16-4-1.
 */
public class TestMsgPack {

	public static void main(String[] args) throws IOException {
		MessagePack msgpack = new MessagePack();

		String abc = new String("abc");
		byte[] bs = msgpack.write(abc);
		String abc1 = msgpack.read(bs, Templates.TString);
		System.out.println(abc1);

		// Create serialize objects.
		List<String> src = new ArrayList<String>();
		src.add("msgpack");
		src.add("kumofs");
		src.add("viver");

		System.out.println(msgpack.read(bs, Templates.TString));
// Serialize
		byte[] raw = msgpack.write(src);

// Deserialize directly using a template
		List<String> dst1 = msgpack.read(raw, Templates.tList(Templates.TString));
		System.out.println(dst1.get(0));
		System.out.println(dst1.get(1));
		System.out.println(dst1.get(2));

// Or, Deserialze to Value then convert type.
		Value dynamic = msgpack.read(raw);
		List<String> dst2 = new Converter(dynamic).read(Templates.tList(Templates.TString));
		System.out.println(dst2.get(0));
		System.out.println(dst2.get(1));
		System.out.println(dst2.get(2));

		Map<String, Object> map = Maps.newHashMap();
		map.put("id", 1);
		map.put("name", "111");

		byte[] maps = msgpack.write(map);
		Value value1 = msgpack.read(maps);

		System.out.println("value1 " + value1);

		Map<String, Object> dstMap = msgpack.read(maps, Templates.tMap(Templates.TString, ObjectTemplate.getInstance()));

		for (Map.Entry<String, Object> entry : dstMap.entrySet()) {
			System.out.println(entry.getKey());
			System.out.println(entry.getValue());
		}
	}
}