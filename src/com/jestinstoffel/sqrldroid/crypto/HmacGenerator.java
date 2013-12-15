package com.jestinstoffel.sqrldroid.crypto;

public interface HmacGenerator {
	byte[] GeneratePrivateKey(byte[] masterKey, String Domain);
}
