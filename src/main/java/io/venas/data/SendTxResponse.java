package io.venas.data;

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SendTxResponse {
	private Map<String,String> hashes;
	private String error;
	private String msg;
	
}
