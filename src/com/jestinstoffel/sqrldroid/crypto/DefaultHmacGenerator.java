package com.jestinstoffel.sqrldroid.crypto;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DefaultHmacGenerator implements HmacGenerator {

	@Override
	public byte[] generatePrivateKey(byte[] masterKey, String Domain) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac hmacSha256 = Mac.getInstance("hmacSHA256");
		SecretKey key = new SecretKeySpec(masterKey, "HmacSHA1");
		hmacSha256.init(key);
		hmacSha256.update(Domain.getBytes(Charset.forName("UTF-8")));
	    return hmacSha256.doFinal();
	}

}
