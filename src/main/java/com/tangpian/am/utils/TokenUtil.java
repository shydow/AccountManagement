package com.tangpian.am.utils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.tangpian.am.exception.EncryptException;
import com.tangpian.am.exception.InvalidKeyAlgorithmException;
import com.tangpian.am.exception.SignatureException;
import com.tangpian.am.model.Message;
import com.tangpian.am.model.TokenSpec;

import net.minidev.json.JSONObject;

public class TokenUtil {

	private static final String KEY_DATA = "data";
	private static final String KEY_VERSION = "version";

	public static String generate(TokenSpec tokenSpec, Object data) {
		String token = null;

		SignedJWT signedJWT;
		try {
			signedJWT = sign(tokenSpec, new Message(data));

		} catch (NoSuchAlgorithmException | InvalidKeySpecException | JOSEException e) {
			e.printStackTrace();
			throw new SignatureException();
		}
		JWEObject jweObject;
		try {
			jweObject = encrypt(tokenSpec.getEncryptKey(), signedJWT);
		} catch (JOSEException e) {
			e.printStackTrace();
			throw new EncryptException();
		}
		token = jweObject.serialize();
		return token;
	}

	public static <T> T parse(TokenSpec tokenSpec, String token, Class<T> clazz) {
		return parse(tokenSpec, token, clazz, false);
	}

	public static <T> T parse(TokenSpec tokenSpec, String token, Class<T> clazz, boolean verifySelf) {

		String verifyKey = null;
		if (verifySelf) {
			verifyKey = tokenSpec.getSelfVerifyKey();
		}
		verifyKey = tokenSpec.getVerifyKey();
		String decryptKey = tokenSpec.getEncryptKey();

		try {
			return parse2Object(token, verifyKey, decryptKey, clazz);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | JOSEException | ParseException e) {
			e.printStackTrace();
			throw new com.tangpian.am.exception.ParseException();
		}
	}

	private static JWEObject encrypt(String encryptKey, SignedJWT signedJWT) throws JOSEException, KeyLengthException {
		JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM).contentType("JWT").build(),
				new Payload(signedJWT));
		jweObject.encrypt(new DirectEncrypter(KeyUtil.keyString2Bytes(encryptKey)));
		return jweObject;
	}

	private static SignedJWT sign(TokenSpec tokenSpec, Message message)
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
		SignedJWT signedJWT = null;
		switch (tokenSpec.getSignatureAlgorithm()) {
		case TokenSpec.SIGNATURE_ALGORITHM_RSA:
			signedJWT = rsaSign(tokenSpec.getSignatureKey(), message);
			break;

		case TokenSpec.SIGNATURE_ALGORITHM_HMAC:
			signedJWT = hmacSign(tokenSpec.getSignatureKey(), message);
			break;

		case TokenSpec.SIGNATURE_ALGORITHM_EC:
			signedJWT = ecSign(tokenSpec.getSignatureKey(), message);
			break;

		default:
			throw new InvalidKeyAlgorithmException();
		}
		return signedJWT;
	}

	private static SignedJWT ecSign(String signatureKey, Message message)
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(KeyUtil.keyString2Bytes(signatureKey));
		KeyFactory keyFactory = KeyFactory.getInstance("EC");

		JWSSigner signer = new ECDSASigner((ECPrivateKey) keyFactory.generatePrivate(keySpec));

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), build(message));

		signedJWT.sign(signer);
		return signedJWT;
	}

	private static SignedJWT hmacSign(String signatureKey, Message message) throws JOSEException {
		JWSSigner signer = new MACSigner(signatureKey);
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), build(message));
		signedJWT.sign(signer);
		return signedJWT;
	}

	private static SignedJWT rsaSign(String signatureKey, Message message)
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(KeyUtil.keyString2Bytes(signatureKey));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		JWSSigner signer = new RSASSASigner(keyFactory.generatePrivate(keySpec));

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), build(message));

		signedJWT.sign(signer);
		return signedJWT;
	}

	private static <T> T parse2Object(String token, String verifyKey, String decryptKey, Class<T> clazz)
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		JSONObject jsonObject = (JSONObject) (parse2Claims(token, verifyKey, decryptKey)).getClaim(KEY_DATA);
		return com.alibaba.fastjson.JSONObject.parseObject(jsonObject.get(KEY_DATA).toString(), clazz);
	}

	private static JWTClaimsSet parse2Claims(String token, String verifyKey, String decryptKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		JWT jwt = JWTParser.parse(token);

		SignedJWT signedJWT = null;
		if (jwt instanceof SignedJWT) {
			signedJWT = (SignedJWT) jwt;
		} else if (jwt instanceof EncryptedJWT) {
			EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;

			if (JWEAlgorithm.Family.RSA.contains(encryptedJWT.getHeader().getAlgorithm())) {
				KeyFactory rsaFactory = KeyFactory.getInstance("RSA");
				PrivateKey rsaPrivateKey = rsaFactory
						.generatePrivate(new PKCS8EncodedKeySpec(KeyUtil.keyString2Bytes(decryptKey)));
				encryptedJWT.decrypt(
						new DefaultJWEDecrypterFactory().createJWEDecrypter(encryptedJWT.getHeader(), rsaPrivateKey));
			} else {
				encryptedJWT.decrypt(new DirectDecrypter(KeyUtil.keyString2Bytes(decryptKey)));
			}

			signedJWT = encryptedJWT.getPayload().toSignedJWT();

		}
		signedJWT.getHeader().getAlgorithm();

		if (JWSAlgorithm.Family.RSA.contains(signedJWT.getHeader().getAlgorithm())) {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			RSAPublicKey publicKey = (RSAPublicKey) factory
					.generatePublic(new X509EncodedKeySpec(KeyUtil.keyString2Bytes(verifyKey)));
			signedJWT.verify(new RSASSAVerifier(publicKey));
		} else if (JWSAlgorithm.Family.EC.contains(signedJWT.getHeader().getAlgorithm())) {
			KeyFactory factory = KeyFactory.getInstance("EC");
			ECPublicKey publicKey = (ECPublicKey) factory
					.generatePublic(new X509EncodedKeySpec(KeyUtil.keyString2Bytes(verifyKey)));
			signedJWT.verify(new ECDSAVerifier(publicKey));
		} else if (JWSAlgorithm.Family.HMAC_SHA.contains(signedJWT.getHeader().getAlgorithm())) {
			signedJWT.verify(new MACVerifier(verifyKey));
		} else {
			throw new com.tangpian.am.exception.ParseException();
		}
		return signedJWT.getJWTClaimsSet();

	}

	private static JWTClaimsSet build(Message message) {
		return transform(message);
	}

	private static JWTClaimsSet transform(Message message) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		Date issueTime = message.getIssueTime();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(issueTime);
		calendar.set(Calendar.DATE, 1);
		Date expirationTime = calendar.getTime();

		builder.issuer(message.getIssuer());
		builder.issueTime(issueTime);
		builder.claim(KEY_VERSION, message.getVersion());
		builder.expirationTime(expirationTime);
		builder.claim(KEY_DATA, message.getData());
		return builder.build();
	}

}
