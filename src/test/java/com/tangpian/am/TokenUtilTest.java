package com.tangpian.am;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JOSEException;
import com.tangpian.am.model.TokenSpec;
import com.tangpian.am.utils.KeyUtil;
import com.tangpian.am.utils.TokenUtil;

public class TokenUtilTest {

	private Map<String, Object> data = new HashMap<>();

	@Before
	public void init() {
		data.put("token", "1234");
	}

	@Test
	public void hmacTokenTest()
			throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_HMAC, TokenSpec.ENCRYPT_ALGORITHM_AES, false);

		test(tokenSpec, data);
	}

	@Test
	public void hmacDymanicTokenTest() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
			ParseException, InvalidAlgorithmParameterException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_HMAC, TokenSpec.ENCRYPT_ALGORITHM_AES, true);

		KeyPair keyPair = KeyUtil.generateTargetKeyPair(KeyUtil.keyString2Bytes(tokenSpec.platFormDhPublicKey));
		tokenSpec.setTenantDhPublicKey(KeyUtil.keyBytes2String(keyPair.getPublic().getEncoded()));

		test(tokenSpec, data);
	}

	@Test
	public void rsaTokenTest() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_RSA, TokenSpec.ENCRYPT_ALGORITHM_AES, false);

		test(tokenSpec, data);
	}

	private void test(TokenSpec tokenSpec, Map<String, Object> data) {
		String token = TokenUtil.generate(tokenSpec, data);
		assertNotNull(token);

		Map<String, Object> result = TokenUtil.parse(tokenSpec, token, true);
		assertEquals(data.get("token"), result.get("token"));
	}

	@Test
	public void ecTokenTest() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_EC, TokenSpec.ENCRYPT_ALGORITHM_AES, false);

		test(tokenSpec, data);
	}

}
