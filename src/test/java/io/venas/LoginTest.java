package io.venas;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class LoginTest {
	public static void main(String[] args) throws Exception {

//		DefaultHttpClient httpclient = new DefaultHttpClient();  
		CloseableHttpClient httpclient = HttpClientBuilder.create().build();

		// 以下是get方法
		HttpGet httpGet = new HttpGet("http://127.0.0.1:7079/api/v2/getuid");
		HttpResponse response = httpclient.execute(httpGet);
		HttpEntity entity = response.getEntity();
		String body = EntityUtils.toString(entity);// 这个就是页面源码了
		httpGet.abort();// 中断请求,接下来可以开始另一段请求
		System.out.println(body);
//			{"uid":"5681675049028962218",
//				"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiI1NjgxNjc1MDQ5MDI4OTYyMjE4IiwiZWNvc3lzdGVtX2lkIjoiMSIsImV4cCI6MTU3MzM3OTg5OH0.DXXRpOIWaKCmGpPbscSCE75y40mj_RIpAZDLeP60KAI"
//					,"network_id":"1"}
		JSONObject getuid = JSON.parseObject(body);
		String token = getuid.getString("token");
		String uid = getuid.getString("uid");
		String network_id = getuid.getString("network_id");
		System.out.println(token);
		System.out.println(uid);
		System.out.println(network_id);
		// httpGet.releaseConnection();//释放请求.如果释放了相当于要清空session

		String private_key = "117f8a1823659836882208d4e13d4bf8652349da349c40e20489a7bd31e01f13";
		// 以下是post方法
		HttpPost httpPost = new HttpPost("http://127.0.0.1:7079/api/v2/login");// 一定要改成可以提交的地址,这里用百度代替

//		String signature = sign(private_key, "LOGIN" + uid);
		String signature = "3044022057032ef3a180b56f1cc4d14891fee94f68701d811824de25b223fbd30d9487a10220725b5c0bf1ed9fbfe79f67b002dd917d87691ff7673410d080e35eff65b92af3";
//		String pubkey = get_public_key(private_key);
		String pubkey = "04872bc5959b7821ff3659ef984cbd1dd7e389995fa4288dd055067b011306beab1cbc2080b326b6267f9421c59aa5a756383e6bc064c7a3388f6a9c72529fa5b2";
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		nvps.add(new BasicNameValuePair("pubkey", pubkey));// 名值对
		nvps.add(new BasicNameValuePair("signature", signature));// 名值对
//		nvps.add(new BasicNameValuePair("token", token));
//		nvps.add(new BasicNameValuePair("uid", uid));
//		nvps.add(new BasicNameValuePair("role_id", "0"));
		nvps.add(new BasicNameValuePair("ecosystem", "1"));
		nvps.add(new BasicNameValuePair("expire", "7776000"));

		httpPost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));
		httpPost.setHeader("Authorization", "Bearer " + token);

		HttpResponse response2 = httpclient.execute(httpPost);
		HttpEntity entity2 = response2.getEntity();
		String body2 = EntityUtils.toString(entity2);
		System.out.println("Login form get: " + response2.getStatusLine());// 这个可以打印状态
		httpPost.abort();
		System.out.println(body2);
		httpPost.releaseConnection();

	}

	private static String get_public_key(String private_key) {

		return null;
	}

	private static String sign(String private_key, String string) {

		return null;
	}

	private void getuid() throws Exception {
	}

	private void login() {

	}
	 
}
