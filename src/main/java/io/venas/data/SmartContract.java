package io.venas.data;

import java.util.Map;

import org.msgpack.annotation.Message;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Message
public class SmartContract {
	private Header Header;
	private Long TokenEcosystem;
	private String MaxSum;
	private String PayOver;
	private Long SignedBy;
	private Map<String, String> Params;

	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	@Message
	public static class Header {
		private Integer ID;
		private Long Time;
		private Long EcosystemID;
		private Long KeyID;
		private Long NetworkID;
		private byte[] PublicKey;
		private String[] PrivateFor;
	}
}
