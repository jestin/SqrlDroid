package com.jestinstoffel.sqrldroid.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public interface HmacGenerator {
	byte[] GeneratePrivateKey(byte[] masterKey, String Domain) throws NoSuchAlgorithmException, InvalidKeyException;
}
