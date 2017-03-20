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
		TokenSpec tokenSpec;
		Map<String, Object> data;
		String token;

		tokenSpec = new TokenSpec();
		KeyPair platformKeyPair = KeyUtil.generateRSAKeyPair(512);
		KeyPair tenantKeyPair = KeyUtil.generateRSAKeyPair(512);
		Key key = KeyUtil.generateAESKey(128);

		String secretKey = KeyUtil.keyBytes2String(key.getEncoded());
		tokenSpec.setEncryption(true);
		tokenSpec.setDymanicSercetKey(false);
		tokenSpec.setEncryptAlgorithm(TokenSpec.ENCRYPT_ALGORITHM_AES);
		tokenSpec.setSignatureAlgorithm(TokenSpec.SIGNATURE_ALGORITHM_RSA);
		tokenSpec.setAesSercetKey(secretKey);
		tokenSpec.setPlatformRsaPrivateKey(KeyUtil.keyBytes2String(platformKeyPair.getPrivate().getEncoded()));
		tokenSpec.setPlatformRsaPublicKey(KeyUtil.keyBytes2String(platformKeyPair.getPublic().getEncoded()));

		tokenSpec.setTenantRsaPrivateKey(KeyUtil.keyBytes2String(tenantKeyPair.getPrivate().getEncoded()));
		tokenSpec.setTenantRsaPublicKey(KeyUtil.keyBytes2String(tenantKeyPair.getPublic().getEncoded()));

		data = new HashMap<>();
		data.put("token", "1234");

		token = TokenUtil.generate(tokenSpec, data);
		System.out.println("*****" + token);

		Date startTime = new Date();
		for (int i = 0; i < 10000; i++) {
			
			token = TokenUtil.generateWithoutDymanicKey(KeyUtil.keyBytes2String(platformKeyPair.getPrivate().getEncoded()),
					secretKey, data);
			System.out.println("*****" + token);

			Map<String, Object> result = TokenUtil.parse(token,
					KeyUtil.keyBytes2String(platformKeyPair.getPublic().getEncoded()), secretKey);
			System.out.println("*****" + result.get("token"));
			
		}
		Date finishTime = new Date();
		System.out.println(finishTime.getTime() - startTime.getTime());
		token = TokenUtil.generateWithoutDymanicKey(KeyUtil.keyBytes2String(platformKeyPair.getPrivate().getEncoded()),
				secretKey, data);
		System.out.println("*****" + token);

		Map<String, Object> result = TokenUtil.parse(token,
				KeyUtil.keyBytes2String(platformKeyPair.getPublic().getEncoded()), secretKey);
		System.out.println("*****" + result.get("token"));
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
