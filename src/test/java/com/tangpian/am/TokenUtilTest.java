package com.tangpian.am;

import java.security.InvalidAlgorithmParameterException;
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
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException, InvalidAlgorithmParameterException {
//		System.out.println("codec");
//		codecProcess();
		System.out.println("hmac");
		hmacTokenTest();
		System.out.println("rsa");
		rsaTokenTest();
		System.out.println("ec");
		ecTokenTest();
		System.out.println("dymanic");
		hmacDymanicTokenTest();
	}

	
	public static void hmacTokenTest()
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_HMAC, TokenSpec.ENCRYPT_ALGORITHM_AES, false);
		Map<String, Object> data = new HashMap<>();
		data.put("token", "1234");
		
		String	token = TokenUtil.generate(tokenSpec, data);
		System.out.println("*****" + token);
		
		Map<String, Object> result = TokenUtil.parse(token,
				tokenSpec.getSignatureAesKey(), tokenSpec.getEncryptAesKey());
		System.out.println("*****" + result.get("token"));
	}
	
	public static void hmacDymanicTokenTest()
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException, InvalidAlgorithmParameterException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_HMAC, TokenSpec.ENCRYPT_ALGORITHM_AES, true);
		Map<String, Object> data = new HashMap<>();
		data.put("token", "1234");
		
		KeyPair keyPair = KeyUtil.generateTargetKeyPair(KeyUtil.keyString2Bytes(tokenSpec.platFormDhPublicKey));
		tokenSpec.setTenantDhPublicKey(KeyUtil.keyBytes2String(keyPair.getPublic().getEncoded()));
		
		String	token = TokenUtil.generate(tokenSpec, data);
		System.out.println("*****" + token);
		
		Map<String, Object> result = TokenUtil.parse(token,
				tokenSpec.getSignatureAesKey(), tokenSpec.getEncryptKey());
		System.out.println("*****" + result.get("token"));
	}
	
	public static void rsaTokenTest()
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_RSA, TokenSpec.ENCRYPT_ALGORITHM_AES, false);
		Map<String, Object> data = new HashMap<>();
		data.put("token", "1234");
		
		String	token = TokenUtil.generate(tokenSpec, data);
		System.out.println("*****" + token);
		
		Map<String, Object> result = TokenUtil.parse(token,
				tokenSpec.getPlatformRsaPublicKey(), tokenSpec.getEncryptAesKey());
		System.out.println("*****" + result.get("token"));
	}
	
	public static void ecTokenTest() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_EC, TokenSpec.ENCRYPT_ALGORITHM_AES, false);
		Map<String, Object> data = new HashMap<>();
		data.put("token", "1234");
		
		String	token = TokenUtil.generate(tokenSpec, data);
		System.out.println("*****" + token);
		
		Map<String, Object> result = TokenUtil.parse(token,
				tokenSpec.getPlatformEcPublicKey(), tokenSpec.getEncryptAesKey());
		System.out.println("*****" + result.get("token"));
	}

//	public static void codecProcess()
//			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
//		KeyPair keyPair = KeyUtil.generateRSAKeyPair(1024);
//		Key key = KeyUtil.generateAESKey(128);
//		Map<String, Object> data = new HashMap<>();
//		data.put("token", "1234");
//
//		String token = TokenUtil.generateWithoutDymanicKey(KeyUtil.keyBytes2String(keyPair.getPrivate().getEncoded()),
//				KeyUtil.keyBytes2String(key.getEncoded()), data);
//		System.out.println(token);
//		System.out.println(TokenUtil.parse(token, KeyUtil.keyBytes2String(keyPair.getPublic().getEncoded()),
//				KeyUtil.keyBytes2String(key.getEncoded())));
//
//	}
}
