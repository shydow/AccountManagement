package com.tangpian.am;

import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.tangpian.am.model.TokenSpec;
import com.tangpian.am.utils.KeyUtil;
import com.tangpian.am.utils.TokenUtil;

public class TokenUtilTest {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		codecProcess();
		tokenProcess();
	}

	public static void tokenProcess()
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_RSA, TokenSpec.ENCRYPT_ALGORITHM_AES, false);
		Map<String, Object> data;
		String token;
		
		data = new HashMap<>();
		data.put("token", "1234");

		token = TokenUtil.generate(tokenSpec, data);
		System.out.println("*****" + token);

		Date startTime = new Date();
		for (int i = 0; i < 10000; i++) {
			
			token = TokenUtil.generateWithoutDymanicKey(tokenSpec.getSignatureKey(), tokenSpec.getEncryptKey(), data);
			System.out.println("*****" + token);

			Map<String, Object> result = TokenUtil.parse(token,
					tokenSpec.getPlatformRsaPublicKey(), tokenSpec.getAesSercetKey());
			System.out.println("*****" + result.get("token"));
			
		}
		Date finishTime = new Date();
		System.out.println(finishTime.getTime() - startTime.getTime());
	}

	public static void codecProcess()
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		KeyPair keyPair = KeyUtil.generateRSAKeyPair(1024);
		Key key = KeyUtil.generateAESKey(128);
		Map<String, Object> data = new HashMap<>();
		data.put("token", "1234");

		String token = TokenUtil.generateWithoutDymanicKey(KeyUtil.keyBytes2String(keyPair.getPrivate().getEncoded()),
				KeyUtil.keyBytes2String(key.getEncoded()), data);
		System.out.println(token);
		System.out.println(TokenUtil.parse(token, KeyUtil.keyBytes2String(keyPair.getPublic().getEncoded()),
				KeyUtil.keyBytes2String(key.getEncoded())));

	}
}
