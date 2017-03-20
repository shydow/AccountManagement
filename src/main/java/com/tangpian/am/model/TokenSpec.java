package com.tangpian.am.model;

import javax.persistence.Embeddable;
import javax.persistence.Transient;

import com.tangpian.am.exception.InvalidEncryptAlgorithmException;
import com.tangpian.am.exception.InvalidSignatureAlgorithmException;
import com.tangpian.am.utils.KeyUtil;

@Embeddable
public class TokenSpec {
	public static final String ENCRYPT_ALGORITHM_AES = "AES";
	public static final String ENCRYPT_ALGORITHM_RSA = "RSA";
	public static final String SIGNATURE_ALGORITHM_HMAC = "HMAC";
	public static final String SIGNATURE_ALGORITHM_EC = "EC";
	public static final String SIGNATURE_ALGORITHM_RSA = "RSA";

	/**
	 * secret key用于加密
	 */
	private String aesSercetKey;
	/**
	 * 是否使用动态安全加密密钥,使用动态密码时需要生成dh key
	 */
	private boolean isDymanicSercetKey;
	private boolean isEncryption;
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

	public String getAesSercetKey() {
		return aesSercetKey;
	}

	public void setAesSercetKey(String aesSercetKey) {
		this.aesSercetKey = aesSercetKey;
	}

	public boolean isDymanicSercetKey() {
		return isDymanicSercetKey;
	}

	public void setDymanicSercetKey(boolean isDymanicSercetKey) {
		this.isDymanicSercetKey = isDymanicSercetKey;
	}

	public boolean isEncryption() {
		return isEncryption;
	}

	public void setEncryption(boolean isEncryption) {
		this.isEncryption = isEncryption;
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
			signatureKey = this.getAesSercetKey();
			break;

		default:
			throw new InvalidSignatureAlgorithmException();
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
			verifyKey = this.getAesSercetKey();
			break;

		default:
			throw new InvalidSignatureAlgorithmException();
		}	
		return verifyKey;
	}

	@Transient
	public String getEncryptKey() {
		String encryptKey = null;
		if (this.isEncryption()) {
			switch (this.getEncryptAlgorithm()) {
			case TokenSpec.ENCRYPT_ALGORITHM_AES:
				encryptKey = this.getAesSercetKey();
				break;

			case TokenSpec.ENCRYPT_ALGORITHM_RSA:
				encryptKey = this.getTenantRsaPublicKey();
				break;

			default:
				throw new InvalidEncryptAlgorithmException();
			}
		}
		return encryptKey;
	}
	
	@Transient
	public String getDecryptKey() {
		String decryptKey = null;
		if (this.isEncryption()) {
			switch (this.getEncryptAlgorithm()) {
			case TokenSpec.ENCRYPT_ALGORITHM_AES:
				decryptKey = this.getAesSercetKey();
				break;

			case TokenSpec.ENCRYPT_ALGORITHM_RSA:
				decryptKey = this.getTenantRsaPublicKey();
				break;

			default:
				throw new InvalidEncryptAlgorithmException();
			}
		}
		return decryptKey;
	}
}