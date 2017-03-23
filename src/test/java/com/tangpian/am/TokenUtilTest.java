package com.tangpian.am;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JOSEException;
import com.tangpian.am.model.Account;
import com.tangpian.am.model.Message;
import com.tangpian.am.model.TokenSpec;
import com.tangpian.am.utils.KeyUtil;
import com.tangpian.am.utils.TokenUtil;

public class TokenUtilTest {

//	private Map<String, Object> data = new HashMap<>();
	private Message<Account> data = new Message();

	@Before
	public void init() {
		Account account = new Account();
		account.setId("1");
		account.setUsername("sam");
		account.setPassword("pass");
		account.setEnabled(true);
		data.setData(account);
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

	private void test(TokenSpec tokenSpec, Message message) {
		String token = TokenUtil.generate(tokenSpec, message);
		assertNotNull(token);
		System.out.println(token);

		Account orgin = data.getData();
		Account result = TokenUtil.parse(tokenSpec, token, Account.class, true);
		assertEquals(orgin.getUsername(), result.getUsername());
	}

	@Test
	public void ecTokenTest() throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
		TokenSpec tokenSpec = new TokenSpec(TokenSpec.SIGNATURE_ALGORITHM_EC, TokenSpec.ENCRYPT_ALGORITHM_AES, false);

		test(tokenSpec, data);
	}

}
