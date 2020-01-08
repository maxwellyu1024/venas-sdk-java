package io.venas.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GetuidResponse {
	// 登录时传递的临时令牌
	// 临时令牌的生命周期为5秒
	private String token;
	// 签名数字
	private String uid;
	// 服务器标识符
	private Long network_id;
}
