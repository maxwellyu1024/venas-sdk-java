package io.venas;

import static io.venas.ECKeyUtil.EncodeLength;
import static io.venas.ECKeyUtil.byteMergerAll;
import static io.venas.ECKeyUtil.getSHA;
import static io.venas.ECKeyUtil.privateKeyHexToPrivateKey;
import static io.venas.ECKeyUtil.privateKeyToPublicKey;
import static io.venas.ECKeyUtil.publicKeyHexToKeyId;
import static io.venas.ECKeyUtil.publicKeyToPublicKeyHex;
import static io.venas.ECKeyUtil.sign;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.msgpack.MessagePack;
import org.msgpack.type.Value;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.Maps;

import io.venas.data.ContractResponse;
import io.venas.data.GetuidResponse;
import io.venas.data.LoginResponse;
import io.venas.data.SendTxResponse;
import io.venas.data.TxstatusResponse;

public class VenasAPI {
	// http://127.0.0.1:7079/api/v2/getuid
	// private static String apiurl = "http://127.0.0.1:7079/api/v2/";
	private static final String apiurl = "http://192.168.1.244:7079/api/v2/";
//	private static final String apiurl = "http://172.16.221.119:7079/api/v2/";

	public interface Config {
		public String Token = "";
		public String KeyId = "";
		public String UID = "";
		public String Ecosystem = "2";
		public String WalletAddress = "";
		public String PrivateKey = "";
		public String PublicKey = "";
	}

	public static GetuidResponse getuid() throws Exception {
		return getRequest("getuid", GetuidResponse.class);
	}

	public static LoginResponse login(GetuidResponse getuid, String publicKeyHex, String signature) throws Exception {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(apiurl + "login");

		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
//		nvps.add(new BasicNameValuePair("role_id", "0"));
		nvps.add(new BasicNameValuePair("ecosystem", "2"));
		nvps.add(new BasicNameValuePair("expire", "7776000"));
		nvps.add(new BasicNameValuePair("pubkey", publicKeyHex));
		// nvps.add(new BasicNameValuePair("key_id", key_id)); // 不能与 pubkey 参数一起使用
		nvps.add(new BasicNameValuePair("signature", signature));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));
		httpPost.setHeader("Authorization", "Bearer " + getuid.getToken());
		CloseableHttpResponse response2 = httpclient.execute(httpPost);
		HttpEntity entity2 = response2.getEntity();
		String body2 = EntityUtils.toString(entity2);
		// System.out.println("Login form get: " + response2.getStatusLine());//
		// 这个可以打印状态
		// System.out.println(body2);
		return JSON.parseObject(body2, LoginResponse.class);
	}

	public static <T> T getRequest(String uri, Class<T> c) throws Exception {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpGet httpGet = new HttpGet(apiurl + uri);
		CloseableHttpResponse response = httpclient.execute(httpGet);
		HttpEntity entity = response.getEntity();
		String body = EntityUtils.toString(entity);
		// System.out.println(body);
		return JSON.parseObject(body, c);
	}

	public static <T> T postRequest(String uri, Class<T> c) {

		return null;
	}

	public static void main(String[] args) throws Exception {

		GetuidResponse getuid = getuid();
		/**
		 * getuid: { "uid":"4584539775596691487", "network_id":"1", "token":
		 * "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiI0NTg0NTM5Nzc1NTk2NjkxNDg3IiwiZWNvc3lzdGVtX2lkIjoiMSIsImV4cCI6MTU3NzM0NDYyN30.nGwaYhHU6z3Uw2hiBgAMcdgTP7AO0L20R3y2s4V8ISQ"
		 * }
		 */
		{
//		String privateKeyHex = "8eec9b9f7e4840fe681f2d991b1a94060a6b03f076e3ac0c9fbfd3095f658004"; //无权限的非生态用户
//			String privateKeyHex = "d0dbd974e62141870a8d6440f34e2ddb79aac12d17caaccd4fcbe0f2724cc169"; // 无权限的生态用户
//		String privateKeyHex = "bd152e646b2d5b714a0f6455164c4c92baa145c9058851e69fc9d027a36229c2"; //生态admin 
//			ECPrivateKeyParameters privateKey = privateKeyHexToPrivateKey(privateKeyHex);
//			ECPublicKeyParameters publicKey = privateKeyToPublicKey(privateKey);
//			String publicKeyHex = publicKeyToPublicKeyHex(publicKey);
		}

		String privateKeyHex = "bd152e646b2d5b714a0f6455164c4c92baa145c9058851e69fc9d027a36229c2";
		ECPrivateKeyParameters privateKey = privateKeyHexToPrivateKey(privateKeyHex);
		ECPublicKeyParameters publicKey = privateKeyToPublicKey(privateKey);
		String publicKeyHex = publicKeyToPublicKeyHex(publicKey);
		String keyId = publicKeyHexToKeyId(publicKeyHex).toString();

		byte[] signBytes = sign(privateKey, new String("LOGIN" + getuid.getNetwork_id() + getuid.getUid()).getBytes());
		String signature = encodeHexString(signBytes);

//		String keyId = publicKeyHexToKeyId(publicKeyHex);

		System.out.println("getuid:\t" + JSON.toJSON(getuid));
		LoginResponse login = login(getuid, publicKeyHex, signature);
		/**
		 * login: {"token":
		 * "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlY29zeXN0ZW1faWQiOiIxIiwia2V5X2lkIjoiNjk2NzQ1ODUzMjEzNjkzNjk1MSIsImFjY291bnRfaWQiOiIwNjk2LTc0NTgtNTMyMS0zNjkzLTY5NTEiLCJyb2xlX2lkIjoiMCIsImV4cCI6MTU3NzM0ODIyM30.6kq0Bt5-F2lUWNcRFBLhQk-GibHzFG6oRD6fqrBikQk"
		 * ,"ecosystem_id":"1","key_id":"6967458532136936951","account":
		 * "0696-7458-5321-3693-6951","notify_key":
		 * "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJTdWIiOiI2OTY3NDU4NTMyMTM2OTM2OTUxIiwiZXhwIjoxNTc3MzQ4MjIzfQ.W45hRm93rB8YlxpjSTd902Mbp9OE2Mpjtdbz8tQ04cc"
		 * ,"isnode":true,"isowner":true,"timestamp":"1577344623","roles":[{"role_id":1,
		 * "role_name":"Admin"},{"role_id":2,"role_name":"Developer"},{"role_id":3,
		 * "role_name":"Consortium Member"},{"role_id":4,"role_name":"Sidechain Node"}]}
		 */
		System.out.println("login:\t" + JSON.toJSON(login));

		ContractResponse contract = contract(login, "MerchantRecordCreate");
		/**
		 * contract: {"walletid":"0","address":"0000-0000-0000-0000-0000",
		 * "tokenid":"1","name":"@2MerchantRecordCreate",
		 * "tableid":"236","id":"5236","state":"2", "fields":[
		 * {"name":"data_content","optional":false,"type":"string"},
		 * {"name":"time","optional":false,"type":"string"}]}
		 * 
		 * 
		 */
		System.out.println("contract:\t" + JSON.toJSON(contract));
		Map<String, Object> form = new HashMap<String, Object>();
		form.put("data_content", "afs1242341");
		form.put("time", "gsdfg");

		SendTxResponse sendTx = sendTx(privateKeyHex, contract, login, getuid, form);
		System.out.println("sendTx:\t" + JSON.toJSON(sendTx));
//		d18fae531ee7723964c8fe18c2b1b6e361d88a4bdc9cd0ff0b58d07eb09df39e
//		3b52b1c9605201da1eb6b9b7843f3584fdb66e44cbff33c75661456b91ca5df5
//		2b1327fcba235f4cd8704eb5acd6b6a459ca86887db7c2d7893fabccf191611d
		TxstatusResponse txstatus = txstatus(login, "629168b88e9a4fedcd92f464ff6492e9d106dc65951269f4a0b48144c9bad604");

		System.out.println("txstatus:\t" + JSON.toJSON(txstatus));
	}

	public static SendTxResponse sendTx(String privateKeyHex, ContractResponse contract, LoginResponse login, GetuidResponse getuid, Map<String, Object> form) throws Exception {

//		String privateKeyHex = "d0dbd974e62141870a8d6440f34e2ddb79aac12d17caaccd4fcbe0f2724cc169";
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
		Header.put("ID", contract.getId());
		Header.put("Time", System.currentTimeMillis() / 1000);
		Header.put("EcosystemID", login.getEcosystem_id());
		Header.put("KeyID", Long.valueOf(keyId));
		Header.put("NetworkID", getuid.getNetwork_id());
		Header.put("PublicKey", publicKey.getQ().getEncoded(false));

		Map<String, Object> Params = Maps.newHashMap();
		body.put("Params", Params);

//		Params.put("data_content", "afsdfads");
//		Params.put("time", "ssssssssssh和额呵呵呵呵");

		form.forEach((key, value) -> {
			Params.put(key, value);
		});

		byte[] data = msgpack.write(body);
		byte[] hash = getSHA(data, "SHA-256");
		hash = getSHA(hash, "SHA-256");

		System.out.println("hash " + Hex.encodeHexString(hash));
		byte[] signature = sign(privateKey, hash);
		// String signature = encodeHexString(signBytes);
		Value value1 = msgpack.read(data);
		// int datalen = data.length;
		// int signlen = signature.length;
		// byte[] let = EncodeLength(231);
		// System.out.println(let);
		System.out.println("value1 " + value1);
		// System.out.println("Time " + System.currentTimeMillis());
		byte[] dataall = byteMergerAll(new byte[] { (byte) 128 }, EncodeLength(data.length), data, EncodeLength(signature.length), signature);

		return sendTx(login, dataall, encodeHexString(hash));
	}

	// http://127.0.0.1:7079/api/v2/contract/{contractname}
	public static ContractResponse contract(LoginResponse login, String contractName) throws Exception {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpGet httpGet = new HttpGet(apiurl + "contract/" + contractName);
		httpGet.setHeader("Authorization", "Bearer " + login.getToken());
		CloseableHttpResponse response2 = httpclient.execute(httpGet);
		HttpEntity entity2 = response2.getEntity();
		String body2 = EntityUtils.toString(entity2);
//		System.out.println(body2);
		return JSON.parseObject(body2, ContractResponse.class);
	}

	// http://127.0.0.1:7079/api/v2/sendTx
	public static SendTxResponse sendTx(LoginResponse login, byte[] data, String hashHex) throws Exception {

		CloseableHttpClient httpClient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(apiurl + "sendTx");
		httpPost.setHeader("Authorization", "Bearer " + login.getToken());
//		httpPost.setHeader("Content-Type", "application/octet-stream");
		MultipartEntityBuilder builder = MultipartEntityBuilder.create();
//		form.forEach((key, value) -> {
//			builder.addTextBody(key, value, ContentType.TEXT_PLAIN);
//		});
		builder.addBinaryBody(hashHex, data, ContentType.DEFAULT_BINARY, "blob");
//		builder.addBinaryBody("data", data);
		// 把文件加到HTTP的post请求中
//		File f = new File(sTestsetFile);
//		builder.addBinaryBody("img", new FileInputStream(f), ContentType.APPLICATION_OCTET_STREAM, f.getName());

		HttpEntity multipart = builder.build();
		httpPost.setEntity(multipart);
		CloseableHttpResponse response = httpClient.execute(httpPost);
		HttpEntity httpEntity = response.getEntity();
		String sResponse = EntityUtils.toString(httpEntity);
		// 打印请求返回的结果
//		System.out.println("Post 返回结果" + sResponse);

		return JSON.parseObject(sResponse, SendTxResponse.class);
	}

	// http://127.0.0.1:7079/api/v2/txstatus
	public static TxstatusResponse txstatus(LoginResponse login, String... hashes) throws Exception {

		CloseableHttpClient httpClient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(apiurl + "txstatus");
		httpPost.setHeader("Authorization", "Bearer " + login.getToken());
//		httpPost.setHeader("Content-Type", "application/octet-stream");
		MultipartEntityBuilder builder = MultipartEntityBuilder.create();
//		form.forEach((key, value) -> {
//			builder.addTextBody(key, value, ContentType.TEXT_PLAIN);
//		});
//		builder.addBinaryBody( "data", data, ContentType.DEFAULT_BINARY,);
		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.addAll(Arrays.asList(hashes));
		jsonObject.put("hashes", jsonArray);
		builder.addTextBody("data", jsonObject.toString());
//		builder.addBinaryBody("data", data);
		// 把文件加到HTTP的post请求中
//		File f = new File(sTestsetFile);
//		builder.addBinaryBody("img", new FileInputStream(f), ContentType.APPLICATION_OCTET_STREAM, f.getName());

		HttpEntity multipart = builder.build();
		httpPost.setEntity(multipart);
		CloseableHttpResponse response = httpClient.execute(httpPost);
		HttpEntity httpEntity = response.getEntity();
		String sResponse = EntityUtils.toString(httpEntity);
		// 打印请求返回的结果
//		System.out.println("Post 返回结果" + sResponse);

		return JSON.parseObject(sResponse, TxstatusResponse.class);

	}

}
