package com.jestinstoffel.sqrldroid.crypto;

public interface PbkdfHandler {
	byte[] generatePasswordKey(String password, byte[] salt);
	boolean verifyPassword(String password, byte[] salt, byte[] partialHash);
	byte[] getPartialHashFromPasswordKey(byte[] passwordKey);
}
