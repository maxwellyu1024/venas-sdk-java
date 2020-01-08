package io.venas.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ContractResponse {
	// VM中合约ID
	private Integer id;
	// 合约所属的生态系统ID
	private String state;
	// contracts 表中合约所在的条目ID
	private String tableid;
	// 合约绑定的账户地址
	private String walletid;
	// 作为支付合约费用的通证所在的生态系统ID
	private String tokenid;
	// 合约绑定的钱包地址 XXXX-...-XXXX
	private String address;
	// 带生态系统ID的合约名称 @1MainCondition
	private String name;
	// 数组中包含合约 data 部分每个参数的结构信息：
	private Field[] fields;

	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	public static class Field {
		// 参数名称
		private String name;
		// 参数类型
		private String type;
		// 参数选项，true 表示可选参数，false 表示必选参数
		private Boolean optional;
	}

}
