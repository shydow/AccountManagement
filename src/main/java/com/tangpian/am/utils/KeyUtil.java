package com.tangpian.am.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.tangpian.am.model.TokenSpec;

public class KeyUtil {
	public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

	public static Key generateAESKey(int keySize) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(keySize);
		return generator.generateKey();
	}
	
	public static KeyPair generateEcKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}
	
	public static Key generateAESKey(int keySize, byte[] seed) throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(keySize, new SecureRandom(seed));
		return generator.generateKey();
	}

	public static KeyPair generateSourceKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

	public static KeyPair generateTargetKeyPair(byte[] publicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		DHParameterSpec dhParameterSpec = ((DHPublicKey) pubKey).getParams();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
		keyPairGenerator.initialize(dhParameterSpec);
		return keyPairGenerator.generateKeyPair();
	}

	public static byte[] generateDhSecretKey(byte[] publicKey, byte[] privateKey)
			throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, InvalidKeySpecException {
		// 实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		// 初始化公钥
		// 密钥材料转换
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
		// 产生公钥
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		// 初始化私钥
		// 密钥材料转换
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);
		// 产生私钥
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
		// 实例化
		KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
		// 初始化
		keyAgree.init(priKey);
		keyAgree.doPhase(pubKey, true);
		// 生成本地密钥
		SecretKey secretKey = keyAgree.generateSecret(TokenSpec.ENCRYPT_ALGORITHM_AES);
		return secretKey.getEncoded();
	}

	/**
	 * 使用公钥加密
	 * 
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] encryptByRSA(byte[] data, byte[] publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException {
		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(x509KeySpec));
		return cipher.doFinal(data);
	}

	/**
	 * 使用密钥解密
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] decryptByRSA(byte[] data, byte[] privateKey)
			throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		/** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(keySpec));
		byte[] b1 = Base64.getDecoder().decode(data);
		/** 执行解密操作 */
		return cipher.doFinal(b1);
	}

	public static byte[] encryptByAES(byte[] data, byte[] secretKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKey secretKeySpec = new SecretKeySpec(secretKey, "AES");
		Cipher cipher = Cipher.getInstance(secretKeySpec.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		return cipher.doFinal(data);
	}

	public static byte[] decryptByAES(byte[] data, byte[] secretKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKey secretKeySpec = new SecretKeySpec(secretKey, "AES");
		Cipher cipher = Cipher.getInstance(secretKeySpec.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		return cipher.doFinal(data);
	}
	
	public static String keyBytes2String(byte[] key) {
		return Base64.getEncoder().encodeToString(key);
	}
	
	public static byte[] keyString2Bytes(String key) {
		return Base64.getDecoder().decode(key);
	}
}
