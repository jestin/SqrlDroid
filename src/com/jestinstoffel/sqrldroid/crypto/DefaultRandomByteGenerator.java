package com.jestinstoffel.sqrldroid.crypto;

import java.security.SecureRandom;

public class DefaultRandomByteGenerator implements RandomByteGenerator {
	
	private SecureRandom mPrng;
	
	public DefaultRandomByteGenerator(){
		mPrng = new SecureRandom();
	}

	@Override
	public void getBytes(byte[] bytes) {
		mPrng.nextBytes(bytes);
	}
}
