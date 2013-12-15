package com.jestinstoffel.sqrldroid;

public interface SqrlClientHandler {
	byte[] CalculateMasterKey(byte[] masterIdentityKey, String password, byte[] salt) throws Exception;
	byte[] CalculateMasterIdentityKey(byte[] masterKey, String password, byte[] salt);
	SqrlData GetSqrlDataForLogin(byte[] masterKey, String url);
	SqrlData GetSqrlDataForLogin(byte[] masterIdentityKey, String password, byte[] salt, String url);
	SqrlData GetSqrlDataForLogin(SqrlIdentity identity, String password, String url);
	SqrlIdentity CreateIdentity(String password, byte[] entropy);
	SqrlIdentity ChangePassword(String oldPassword, byte[] oldSalt, String newPassword, byte[] masterIdentityKey);
	boolean VerifyPassword(String password, SqrlIdentity identity);
	String GetDomainFromUrl(String url);
}
