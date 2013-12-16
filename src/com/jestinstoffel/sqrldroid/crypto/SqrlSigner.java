package com.jestinstoffel.sqrldroid.crypto;

public interface SqrlSigner {
	byte[] sign(byte[] privateKey, byte[] message);
	byte[] sign(byte[] privateKey, String message);
	byte[] verify(byte[] publicKey, byte[] signedMessage);
	byte[] makePublicKey(byte[] privateKey);
}
