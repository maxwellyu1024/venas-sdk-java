package io.venas;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.msgpack.MessagePack;
import org.msgpack.template.Templates;
import org.msgpack.type.Value;
import org.msgpack.unpacker.Converter;

import com.google.common.collect.Maps;

import static io.venas.ECKeyUtil.privateKeyHexToPrivateKey;
import static io.venas.ECKeyUtil.privateKeyToPublicKey;
import static io.venas.ECKeyUtil.publicKeyToPublicKeyHex;
import static io.venas.ECKeyUtil.publicKeyHexToKeyId;
import static io.venas.ECKeyUtil.sign;
import static io.venas.ECKeyUtil.byteMergerAll;
import static io.venas.ECKeyUtil.getSHA;
import static io.venas.ECKeyUtil.EncodeLength;
import static io.venas.ECKeyUtil.getPrintHex;
import static io.venas.ECKeyUtil.intToBigEndianBytes;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by wangdi on 16-4-1.
 */
public class TestMsgPack2 {

	public static void main(String[] args) throws Exception {

		String privateKeyHex = "d0dbd974e62141870a8d6440f34e2ddb79aac12d17caaccd4fcbe0f2724cc169";
		ECPrivateKeyParameters privateKey = privateKeyHexToPrivateKey(privateKeyHex);
		ECPublicKeyParameters publicKey = privateKeyToPublicKey(privateKey);
		String publicKeyHex = publicKeyToPublicKeyHex(publicKey);
		String keyId = publicKeyHexToKeyId(publicKeyHex).toString();

		MessagePack msgpack = new MessagePack();

		Map<String, Object> body = Maps.newHashMap();
		Map<String, Object> Header = Maps.newHashMap();
		body.put("Header", Header);
		/**
		 * <pre>
		   {
			"Header": {
				"ID": 5236,
				"Time": 1578033653,
				"EcosystemID": 1,
				"KeyID": 1087716497586429813,
				"NetworkID": 0,
				"PublicKey": "W<=)\u0007i>QDOOW\t`[5OA&\u001Dj˝a!NbYe\u0014v}B\u0011e:",
				"PrivateFor": null
			},
			"TokenEcosystem": 0,
			"MaxSum": "",
			"PayOver": "",
			"SignedBy": 0,
			"Params": {
				"data_content": "asd",
				"time": "21432"
			}
		}
		 * </pre>
		 */
		Header.put("ID", 5236);
		Header.put("Time", System.currentTimeMillis());
		Header.put("EcosystemID", 1);
		Header.put("KeyID", Long.valueOf(keyId));
		Header.put("NetworkID", 0);
		Header.put("PublicKey", publicKey.getQ().getEncoded(false));

		Map<String, Object> Params = Maps.newHashMap();
		body.put("Params", Params);

		Params.put("data_content", "afsdfads");
		Params.put("time", "ssssssssssh和额呵呵呵呵");

		byte[] data = msgpack.write(body);
		byte[] hash = getSHA(data, "SHA-256");
		hash = getSHA(hash, "SHA-256");

		byte[] signature = sign(privateKey, hash);
		// String signature = encodeHexString(signBytes);
		// Value value1 = msgpack.read(data);
		// int datalen = data.length;
		// int signlen = signature.length;
		// byte[] let = EncodeLength(231);
		// System.out.println(let);
		// System.out.println("value1 " + value1);
		// System.out.println("Time " + System.currentTimeMillis());
		byte[] dataall = byteMergerAll(new byte[] { (byte) 128 }, EncodeLength(data.length), data, EncodeLength(signature.length), signature);

		System.out.println("data " + getPrintHex(dataall));

	}

}