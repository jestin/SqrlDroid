package com.jestinstoffel.sqrldroid.crypto;

public interface SqrlSigner {
	byte[] Sign(byte[] privateKey, byte[] message);
	byte[] Sign(byte[] privateKey, String message);
	byte[] Verify(byte[] publicKey, byte[] signedMessage);
	byte[] MakePublicKey(byte[] privateKey);
}
