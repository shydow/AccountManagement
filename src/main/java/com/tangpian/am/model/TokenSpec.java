package com.tangpian.am.model;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.persistence.Embeddable;
import javax.persistence.Transient;

import com.tangpian.am.exception.InvalidKeyAlgorithmException;
import com.tangpian.am.exception.KeyException;
import com.tangpian.am.utils.KeyUtil;

@Embeddable
public class TokenSpec {
	private static Map<String, String> dymanicKeyCache = new HashMap<>();
	
	public static final String ENCRYPT_ALGORITHM_AES = "AES";
	// public static final String ENCRYPT_ALGORITHM_RSA = "RSA";
	public static final String SIGNATURE_ALGORITHM_HMAC = "HMAC";
	public static final String SIGNATURE_ALGORITHM_EC = "EC";
	public static final String SIGNATURE_ALGORITHM_RSA = "RSA";

	private static final int DEFAULT_ENCRYPT_AES_KEY_SIZE = 128;
	private static final int DEFAULT_SIGNATURE_AES_KEY_SIZE = 256;
	private static final int DEFAULT_RSA_KEY_SIZE = 1024;
	private static final int DEFAULT_EC_KEY_SIZE = 256;
	private static final int DEFAULT_DH_KEY_SIZE = 512;

	/**
	 * TokenSpec 用于管理token相关的
	 * 
	 * @param signatureAlgorithm
	 * @param encryptAlgorithm
	 */
	public TokenSpec(String signatureAlgorithm, String encryptAlgorithm) {
		new TokenSpec(signatureAlgorithm, encryptAlgorithm, false);
	}

	public TokenSpec(String signatureAlgorithm, String encryptAlgorithm, boolean isDymanicSercetKey) {
		try {
			this.isDymanicSercetKey = isDymanicSercetKey;
			if (isDymanicSercetKey) {
				initDhKey();
			}
			initSignatureKey(signatureAlgorithm);
			initEncryptKey(encryptAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new InvalidKeyAlgorithmException();
		}
	}

	private void initEncryptKey(String encryptAlgorithm) throws NoSuchAlgorithmException {
		this.encryptAlgorithm = encryptAlgorithm;
		switch (encryptAlgorithm) {

		case ENCRYPT_ALGORITHM_AES:
			initEncryptAesKey();
			break;

		default:
			break;
		}
	}

	private void initDhKey() throws NoSuchAlgorithmException {
		KeyPair dhSourceKeyPair = KeyUtil.generateSourceKeyPair(DEFAULT_DH_KEY_SIZE);
		this.platformDhPrivateKey = KeyUtil.keyBytes2String(dhSourceKeyPair.getPrivate().getEncoded());
		this.platFormDhPublicKey = KeyUtil.keyBytes2String(dhSourceKeyPair.getPublic().getEncoded());
	}

	private void initSignatureKey(String signatureAlgorithm) throws NoSuchAlgorithmException {

		this.signatureAlgorithm = signatureAlgorithm;
		switch (signatureAlgorithm) {
		case SIGNATURE_ALGORITHM_EC:
			initEcKey();
			break;

		case SIGNATURE_ALGORITHM_RSA:
			initRsaKey();
			break;

		case SIGNATURE_ALGORITHM_HMAC:
			initSignatureAesKey();
			break;

		default:
			throw new InvalidKeyAlgorithmException();
		}
	}

	private void initEncryptAesKey() throws NoSuchAlgorithmException {
		Key aesKey = KeyUtil.generateAESKey(DEFAULT_ENCRYPT_AES_KEY_SIZE);
		this.encryptAesKey = KeyUtil.keyBytes2String(aesKey.getEncoded());
	}
	
	private void initSignatureAesKey() throws NoSuchAlgorithmException {
		Key aesKey = KeyUtil.generateAESKey(DEFAULT_SIGNATURE_AES_KEY_SIZE);
		this.signatureAesKey = KeyUtil.keyBytes2String(aesKey.getEncoded());
	}

	private void initEcKey() throws NoSuchAlgorithmException {
		KeyPair ecPlatformKeyPair = KeyUtil.generateEcKeyPair(DEFAULT_EC_KEY_SIZE);
		KeyPair ecTenantKeyPair = KeyUtil.generateEcKeyPair(DEFAULT_EC_KEY_SIZE);

		this.platformEcPrivateKey = KeyUtil.keyBytes2String(ecPlatformKeyPair.getPrivate().getEncoded());
		this.platformEcPublicKey = KeyUtil.keyBytes2String(ecPlatformKeyPair.getPublic().getEncoded());

		this.tenantEcPrivateKey = KeyUtil.keyBytes2String(ecTenantKeyPair.getPrivate().getEncoded());
		this.tenantEcPublicKey = KeyUtil.keyBytes2String(ecTenantKeyPair.getPublic().getEncoded());
	}

	private void initRsaKey() throws NoSuchAlgorithmException {
		KeyPair rsaPlatformKeyPair = KeyUtil.generateRSAKeyPair(DEFAULT_RSA_KEY_SIZE);
		KeyPair rsaTenantKeyPair = KeyUtil.generateRSAKeyPair(DEFAULT_RSA_KEY_SIZE);

		this.platformRsaPrivateKey = KeyUtil.keyBytes2String(rsaPlatformKeyPair.getPrivate().getEncoded());
		this.platformRsaPublicKey = KeyUtil.keyBytes2String(rsaPlatformKeyPair.getPublic().getEncoded());

		this.tenantRsaPrivateKey = KeyUtil.keyBytes2String(rsaTenantKeyPair.getPrivate().getEncoded());
		this.tenantRsaPublicKey = KeyUtil.keyBytes2String(rsaTenantKeyPair.getPublic().getEncoded());
	}

	private String signatureAesKey;
	/**
	 * secret key用于加密
	 */
	private String encryptAesKey;
	/**
	 * 是否使用动态安全加密密钥,使用动态密码时需要生成dh key
	 */
	private boolean isDymanicSercetKey;
	private String signatureAlgorithm;
	private String encryptAlgorithm;
	/**
	 * public/private key 用于客户端签名和验签
	 */
	private String tenantRsaPublicKey;
	@Transient
	private String tenantRsaPrivateKey;
	private String platformRsaPublicKey;
	private String platformRsaPrivateKey;

	private String tenantEcPublicKey;
	@Transient
	private String tenantEcPrivateKey;
	private String platformEcPublicKey;
	private String platformEcPrivateKey;
	/**
	 * dh key用于交换安全加密密钥
	 */
	public String platFormDhPublicKey;
	public String platformDhPrivateKey;
	public String tenantDhPublicKey;

	public boolean isDymanicSercetKey() {
		return isDymanicSercetKey;
	}

	public void setDymanicSercetKey(boolean isDymanicSercetKey) {
		this.isDymanicSercetKey = isDymanicSercetKey;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String getEncryptAlgorithm() {
		return encryptAlgorithm;
	}

	public void setEncryptAlgorithm(String encryptAlgorithm) {
		this.encryptAlgorithm = encryptAlgorithm;
	}

	public String getTenantRsaPublicKey() {
		return tenantRsaPublicKey;
	}

	public void setTenantRsaPublicKey(String tenantRsaPublicKey) {
		this.tenantRsaPublicKey = tenantRsaPublicKey;
	}

	public String getTenantRsaPrivateKey() {
		return tenantRsaPrivateKey;
	}

	public void setTenantRsaPrivateKey(String tenantRsaPrivateKey) {
		this.tenantRsaPrivateKey = tenantRsaPrivateKey;
	}

	public String getPlatformRsaPublicKey() {
		return platformRsaPublicKey;
	}

	public void setPlatformRsaPublicKey(String platformRsaPublicKey) {
		this.platformRsaPublicKey = platformRsaPublicKey;
	}

	public String getPlatformRsaPrivateKey() {
		return platformRsaPrivateKey;
	}

	public void setPlatformRsaPrivateKey(String platformRsaPrivateKey) {
		this.platformRsaPrivateKey = platformRsaPrivateKey;
	}

	public String getPlatFormDhPublicKey() {
		return platFormDhPublicKey;
	}

	public void setPlatFormDhPublicKey(String platFormDhPublicKey) {
		this.platFormDhPublicKey = platFormDhPublicKey;
	}

	public String getPlatformDhPrivateKey() {
		return platformDhPrivateKey;
	}

	public void setPlatformDhPrivateKey(String platformDhPrivateKey) {
		this.platformDhPrivateKey = platformDhPrivateKey;
	}

	public String getTenantDhPublicKey() {
		return tenantDhPublicKey;
	}

	public void setTenantDhPublicKey(String tenantDhPublicKey) {
		this.tenantDhPublicKey = tenantDhPublicKey;
	}

	public String getTenantEcPublicKey() {
		return tenantEcPublicKey;
	}

	public void setTenantEcPublicKey(String tenantEcPublicKey) {
		this.tenantEcPublicKey = tenantEcPublicKey;
	}

	public String getTenantEcPrivateKey() {
		return tenantEcPrivateKey;
	}

	public void setTenantEcPrivateKey(String tenantEcPrivateKey) {
		this.tenantEcPrivateKey = tenantEcPrivateKey;
	}

	public String getPlatformEcPublicKey() {
		return platformEcPublicKey;
	}

	public void setPlatformEcPublicKey(String platformEcPublicKey) {
		this.platformEcPublicKey = platformEcPublicKey;
	}

	public String getPlatformEcPrivateKey() {
		return platformEcPrivateKey;
	}

	public void setPlatformEcPrivateKey(String platformEcPrivateKey) {
		this.platformEcPrivateKey = platformEcPrivateKey;
	}

	@Transient
	public String getSignatureKey() {
		String signatureKey = null;
		switch (this.getSignatureAlgorithm()) {
		case TokenSpec.SIGNATURE_ALGORITHM_RSA:
			signatureKey = this.getPlatformRsaPrivateKey();
			break;

		case TokenSpec.SIGNATURE_ALGORITHM_EC:
			signatureKey = this.getPlatformEcPrivateKey();
			break;

		case TokenSpec.SIGNATURE_ALGORITHM_HMAC:
			signatureKey = this.getSignatureAesKey();
			break;

		default:
			throw new InvalidKeyAlgorithmException();
		}
		return signatureKey;
	}

	@Transient
	public String getVerifyKey() {
		String verifyKey = null;
		switch (this.getSignatureAlgorithm()) {
		case TokenSpec.SIGNATURE_ALGORITHM_RSA:
			verifyKey = this.getTenantRsaPublicKey();
			break;

		case TokenSpec.SIGNATURE_ALGORITHM_EC:
			verifyKey = this.getTenantEcPublicKey();
			break;

		case TokenSpec.SIGNATURE_ALGORITHM_HMAC:
			verifyKey = this.getSignatureAesKey();
			break;

		default:
			throw new InvalidKeyAlgorithmException();
		}
		return verifyKey;
	}

	@Transient
	public String getEncryptKey() {
		String encryptKey = null;
		if (isDymanicSercetKey) {
			try {
				encryptKey = generateDymanicSecretKey(this);
			} catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException
					| InvalidKeySpecException e) {
				e.printStackTrace();
				throw new KeyException();
			}
	 	} else {
			switch (this.getEncryptAlgorithm()) {
			case TokenSpec.ENCRYPT_ALGORITHM_AES:
				encryptKey = this.getEncryptAesKey();
				break;

			default:
				throw new InvalidKeyAlgorithmException();
			}	 		
	 	}
		return encryptKey;
	}

	private String generateDymanicSecretKey(TokenSpec tokenSpec) throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, InvalidKeySpecException {
		String platformPrivateKey = tokenSpec.getPlatformDhPrivateKey();
		String tenantPublicKey = tokenSpec.getTenantDhPublicKey();
		String encryptKey = searchDymanicKeyCache(platformPrivateKey, tenantPublicKey);
		if (encryptKey == null) {
			byte[] seed = KeyUtil.generateDhSecretKey(KeyUtil.keyString2Bytes(tenantPublicKey), KeyUtil.keyString2Bytes(platformPrivateKey));
			encryptKey = KeyUtil.keyBytes2String(KeyUtil.generateAESKey(DEFAULT_ENCRYPT_AES_KEY_SIZE, seed).getEncoded());
			updateDymanicKeyCache(platformPrivateKey, tenantPublicKey, encryptKey);
		}
		return encryptKey;
	}
	
	private String searchDymanicKeyCache(String platformPrivateKey, String tenantPublicKey) {
		return dymanicKeyCache.get(platformPrivateKey + "||" + tenantPublicKey);
	}
	
	private void updateDymanicKeyCache(String platformPrivateKey, String tenantPublicKey, String secretKey) {
		dymanicKeyCache.put(platformPrivateKey + "||" + tenantPublicKey, secretKey);
	}

	@Transient
	public String getDecryptKey() {
		String decryptKey = null;
		switch (this.getEncryptAlgorithm()) {
		case TokenSpec.ENCRYPT_ALGORITHM_AES:
			decryptKey = this.getEncryptAesKey();
			break;

		default:
			throw new InvalidKeyAlgorithmException();
		}
		return decryptKey;
	}

	public String getSignatureAesKey() {
		return signatureAesKey;
	}

	public void setSignatureAesKey(String signatureAesKey) {
		this.signatureAesKey = signatureAesKey;
	}

	public String getEncryptAesKey() {
		return encryptAesKey;
	}

	public void setEncryptAesKey(String encryptAesKey) {
		this.encryptAesKey = encryptAesKey;
	}
}