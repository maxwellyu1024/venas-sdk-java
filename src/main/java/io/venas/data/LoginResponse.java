package io.venas.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
	// JWT令牌
	private String token;
	// 生态系统ID
	private Long ecosystem_id;
	// 账户地址ID
	private String key_id;
	// 钱包地址 XXXX-XXXX-.....-XXXX
	private String account;
	// 通知ID
	private String notify_key;
	// 该账户地址是否是该节点的所有者值： true,false
	private String isnode;
	// 该账户地址是否是该生态系统的创建者值： true,false
	private String isowner;
	private String timestamp;
	private Role[] roles;

	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	public static class Role {
		private String role_id;
		private String role_name;
	}
}
