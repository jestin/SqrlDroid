package com.jestinstoffel.sqrldroid.crypto;

public interface PbkdfHandler {
	byte[] GeneratePasswordKey(String password, byte[] salt);
	boolean VerifyPassword(String password, byte[] salt, byte[] partialHash);
	byte[] GetPartialHashFromPasswordKey(byte[] passwordKey);
}
