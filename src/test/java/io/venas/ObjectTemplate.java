package io.venas;

import org.msgpack.MessageTypeException;
import org.msgpack.packer.Packer;
import org.msgpack.template.AbstractTemplate;
import org.msgpack.template.Templates;
import org.msgpack.type.*;
import org.msgpack.unpacker.Converter;
import org.msgpack.unpacker.Unpacker;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * msgpack template支持 java Object类型
 */
public class ObjectTemplate extends AbstractTemplate<Object> {

	static final ObjectTemplate instance = new ObjectTemplate();

	public static final ObjectTemplate OBJECT_TEMPLATE = ObjectTemplate.getInstance();

	private ObjectTemplate() {
	}

	static public ObjectTemplate getInstance() {
		return instance;
	}

	@Override
	public void write(Packer pk, Object v, boolean required) throws IOException {
		if (v == null) {
			if (required) {
				throw new MessageTypeException("Attempted to write null");
			}
			pk.writeNil();
			return;
		}
		pk.write(v);
	}

	@Override
	public Object read(Unpacker u, Object to, boolean required) throws IOException {
		if (!required && u.trySkipNil()) {
			return null;
		}

		return toObject(u.readValue());
	}

	private static Object toObject(Value value) throws IOException {
		Converter conv = new Converter(value);
		System.out.println("toObject " + value+"   "+value.getClass());
		if (value.isNilValue()) { // null
			return null;
		} else if (value.isRawValue()) { // byte[] or String or maybe Date?
			// deserialize value to String object
//			if (value.getClass().getSimpleName().equals("ByteArrayRawValueImpl")) {
//				RawValue v = value.asRawValue();
//				return conv.read(Templates.TByteArray);
//			}else {
				RawValue v = value.asRawValue();
				return conv.read(Templates.TString);
//			}
		} else if (value.isBooleanValue()) { // boolean
			return conv.read(Templates.TBoolean);
		} else if (value.isIntegerValue()) { // int or long or BigInteger
			// deserialize value to int
//			if (value.getClass().getSimpleName().equals("LongValueImpl")) {
//				IntegerValue v = value.asIntegerValue();
//				return conv.read(Templates.TLong);
//			} else {
				IntegerValue v = value.asIntegerValue();
				return conv.read(Templates.TInteger);
//			}
		} else if (value.isFloatValue()) { // float or double
			// deserialize value to double
			FloatValue v = value.asFloatValue();
			return conv.read(Templates.TDouble);
		} else if (value.isArrayValue()) { // List or Set
			// deserialize value to List object
			ArrayValue v = value.asArrayValue();
			List<Object> ret = new ArrayList<Object>(v.size());
			for (Value elementValue : v) {
				ret.add(toObject(elementValue));
			}
			return ret;
		} else if (value.isMapValue()) { // Map
			MapValue v = value.asMapValue();

//            Map map = new HashMap<>(v.size());
			Map map = new HashMap(v.size());
			for (Map.Entry<Value, Value> entry : v.entrySet()) {
				Value key = entry.getKey();
				Value val = entry.getValue();
				System.out.println("key " + key + "  val " + val + "  valclass " + val.getClass());
				if (key.toString().equals("\"PublicKey\"")) {
					System.out.println(key);
				}
				map.put(toObject(key), toObject(val));
//				map.put(key, val);
			}
			return map;
		} else {
			throw new RuntimeException("fatal error");
		}
	}
}