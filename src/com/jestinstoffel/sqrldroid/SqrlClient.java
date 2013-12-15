package com.jestinstoffel.sqrldroid;

import java.util.Arrays;

import com.jestinstoffel.sqrldroid.crypto.HmacGenerator;
import com.jestinstoffel.sqrldroid.crypto.PbkdfHandler;
import com.jestinstoffel.sqrldroid.crypto.SqrlSigner;

public class SqrlClient implements SqrlClientHandler {
	
	private HmacGenerator mHmac;
	private PbkdfHandler mPbkdf;
	private SqrlSigner mSigner;
	
	public SqrlClient(
			HmacGenerator hmac,
			PbkdfHandler pbkdf,
			SqrlSigner signer){
		mHmac = hmac;
		mPbkdf = pbkdf;
		mSigner = signer;
	}

	@Override
	public byte[] CalculateMasterKey(byte[] masterIdentityKey, String password, byte[] salt) throws Exception {
		if(masterIdentityKey.length != 32)
		{
			throw new Exception("master identity key must be 256 bits (32 bytes).");
		}

		byte[] passwordKey = mPbkdf.GeneratePasswordKey(password, salt);

		if(passwordKey.length != 32)
		{
			throw new Exception("password key must be 256 bits (32 bytes).  Check validity of PBKDF.");
		}

		byte[] masterKey = Xor(masterIdentityKey, passwordKey);

		Arrays.fill(passwordKey, (byte)0);

		return masterKey;
	}

	@Override
	public byte[] CalculateMasterIdentityKey(byte[] masterKey, String password,
			byte[] salt) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SqrlData GetSqrlDataForLogin(byte[] masterKey, String url) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SqrlData GetSqrlDataForLogin(byte[] masterIdentityKey,
			String password, byte[] salt, String url) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SqrlData GetSqrlDataForLogin(SqrlIdentity identity, String password,
			String url) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SqrlIdentity CreateIdentity(String password, byte[] entropy) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SqrlIdentity ChangePassword(String oldPassword, byte[] oldSalt,
			String newPassword, byte[] masterIdentityKey) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean VerifyPassword(String password, SqrlIdentity identity) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String GetDomainFromUrl(String url) {
		// TODO Auto-generated method stub
		return null;
	}

	private byte[] Xor(byte[] a, byte[] b) throws Exception
	{
		if(a.length != b.length)
		{
			throw new Exception("a and b must be of the same length");
		}

		byte[] result = new byte[a.length];

		for(int i = 0; i < a.length; i++)
		{
			result[i] = (byte)(a[i] ^ b[i]);
		}

		return result;
	}
}
