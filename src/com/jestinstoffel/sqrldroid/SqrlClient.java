package com.jestinstoffel.sqrldroid;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

import com.jestinstoffel.sqrldroid.crypto.HmacGenerator;
import com.jestinstoffel.sqrldroid.crypto.PbkdfHandler;
import com.jestinstoffel.sqrldroid.crypto.RandomByteGenerator;
import com.jestinstoffel.sqrldroid.crypto.SqrlSigner;

public class SqrlClient implements SqrlClientHandler {
	
	private HmacGenerator mHmac;
	private PbkdfHandler mPbkdf;
	private SqrlSigner mSigner;
	private RandomByteGenerator mPrng;
	
	public SqrlClient(
			HmacGenerator hmac,
			PbkdfHandler pbkdf,
			SqrlSigner signer,
			RandomByteGenerator prng){
		mHmac = hmac;
		mPbkdf = pbkdf;
		mSigner = signer;
		mPrng = prng;
	}

	@Override
	public byte[] calculateMasterKey(byte[] masterIdentityKey, String password, byte[] salt) throws Exception {
		if(masterIdentityKey.length != 32)
		{
			throw new Exception("master identity key must be 256 bits (32 bytes).");
		}

		byte[] passwordKey = mPbkdf.generatePasswordKey(password, salt);

		if(passwordKey.length != 32)
		{
			throw new Exception("password key must be 256 bits (32 bytes).  Check validity of PBKDF.");
		}

		byte[] masterKey = Xor(masterIdentityKey, passwordKey);

		Arrays.fill(passwordKey, (byte)0);

		return masterKey;
	}

	@Override
	public byte[] calculateMasterIdentityKey(byte[] masterKey, String password, byte[] salt) throws Exception {
		if(masterKey.length != 32)
		{
			throw new Exception("master key must be 256 bits (32 bytes).");
		}

		byte[] passwordKey = mPbkdf.generatePasswordKey(password, salt);

		if(passwordKey.length != 32)
		{
			throw new Exception("password key must be 256 bits (32 bytes).  Check validity of PBKDF.");
		}

		byte[] masterIdentityKey = Xor(masterKey, passwordKey);

		Arrays.fill(passwordKey, (byte)0);

		return masterIdentityKey;
	}

	@Override
	public SqrlData getSqrlDataForLogin(byte[] masterKey, String url) throws Exception {
		String domain = getDomainFromUrl(url);
		byte[] privateKey = mHmac.generatePrivateKey(masterKey, domain);

		SqrlData sqrlData = new SqrlData();
		sqrlData.url = GetUrlWithoutProtocol(url);
		sqrlData.signature = mSigner.sign(privateKey, GetUrlWithoutProtocol(url));
		sqrlData.publicKey = mSigner.makePublicKey(privateKey);

		Arrays.fill(privateKey, (byte)0);

		return sqrlData;
	}

	@Override
	public SqrlData getSqrlDataForLogin(byte[] masterIdentityKey, String password, byte[] salt, String url) throws Exception {
		byte[] masterKey = calculateMasterKey(masterIdentityKey, password, salt);
		SqrlData sqrlData = getSqrlDataForLogin(masterKey, url);

		Arrays.fill(masterKey, (byte)0);

		return sqrlData;
	}

	@Override
	public SqrlData getSqrlDataForLogin(SqrlIdentity identity, String password, String url) throws Exception {
		return getSqrlDataForLogin(identity.masterIdentityKey, password, identity.salt, url);
	}

	@Override
	public SqrlIdentity createIdentity(String password, byte[] entropy) throws Exception {
		SqrlIdentity identity = new SqrlIdentity();

		identity.salt = new byte[8];
		byte[] masterKey = new byte[32];

		MessageDigest md = MessageDigest.getInstance("SHA-256");

		mPrng.getBytes(identity.salt);
		mPrng.getBytes(masterKey);

		// XOR the generated master key with the entropy (making any potential backdoors in the implementation of SecureRandom irrelevent)
		masterKey = Xor(masterKey, md.digest(entropy));

		// call the SCrypt PBKDF to create the password key
		byte[] passwordKey = mPbkdf.generatePasswordKey(password, identity.salt);

		// get the partial hash for password verification
		identity.partialPasswordHash = mPbkdf.getPartialHashFromPasswordKey(passwordKey);

		// XOR the master key and the password key to get the master identity key
		identity.masterIdentityKey = Xor(passwordKey, masterKey);

		Arrays.fill(masterKey, (byte)0);
		Arrays.fill(passwordKey, (byte)0);

		return identity;
	}

	@Override
	public SqrlIdentity changePassword(String oldPassword, byte[] oldSalt, String newPassword, byte[] masterIdentityKey) throws Exception {
		SqrlIdentity identity = new SqrlIdentity();

		// calculate the master key
		byte[] oldPasswordKey = mPbkdf.generatePasswordKey(oldPassword, oldSalt);
		byte[] masterKey = Xor(oldPasswordKey, masterIdentityKey);

		// generate new salt
		identity.salt = new byte[8];
		mPrng.getBytes(identity.salt);

		// generate the new password key
		byte[] newPasswordKey = mPbkdf.generatePasswordKey(newPassword, identity.salt);

		// get the partial hash for password verification
		identity.partialPasswordHash = mPbkdf.getPartialHashFromPasswordKey(newPasswordKey);

		// XOR the master key and the new password key to get the master identity key
		identity.masterIdentityKey = Xor(newPasswordKey, masterKey);

		Arrays.fill(masterKey, (byte)0);
		Arrays.fill(oldPasswordKey, (byte)0);
		Arrays.fill(newPasswordKey, (byte)0);

		return identity;
	}

	@Override
	public boolean verifyPassword(String password, SqrlIdentity identity) {
		return mPbkdf.verifyPassword(password, identity.salt, identity.partialPasswordHash);
	}

	@Override
	public String getDomainFromUrl(String url) throws Exception {
		// strip off scheme
		String domain = GetUrlWithoutProtocol(url);

		int pipeIndex = domain.indexOf('|');

		if(pipeIndex >= 0)
		{
			return domain.substring(0, pipeIndex);
		}

		int slashIndex = domain.indexOf('/');

		if(slashIndex < 0)
		{
			throw new Exception("SQRL urls must contain a '/'");
		}

		return domain.substring(0, slashIndex);
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
	
	private String GetUrlWithoutProtocol(String url) throws Exception {
		// only use this variable for validity checking, never for any cryptographic features because toLower() will modify nonces
		String lowerUrl = url.toLowerCase(Locale.ENGLISH);

		if(lowerUrl.startsWith("sqrl://"))
		{
			return url.substring(7);
		}

		if(lowerUrl.startsWith("qrl://"))
		{
			return url.substring(6);
		}

		throw new Exception("SQRL urls must begin with 'sqrl://' or 'qrl://'");
	}
}
