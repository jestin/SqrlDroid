package com.jestinstoffel.sqrldroid;

public interface SqrlClientHandler {
	byte[] CalculateMasterKey(byte[] masterIdentityKey, String password, byte[] salt) throws Exception;
	byte[] CalculateMasterIdentityKey(byte[] masterKey, String password, byte[] salt) throws Exception;
	SqrlData GetSqrlDataForLogin(byte[] masterKey, String url) throws Exception;
	SqrlData GetSqrlDataForLogin(byte[] masterIdentityKey, String password, byte[] salt, String url) throws Exception;
	SqrlData GetSqrlDataForLogin(SqrlIdentity identity, String password, String url) throws Exception;
	SqrlIdentity CreateIdentity(String password, byte[] entropy) throws Exception;
	SqrlIdentity ChangePassword(String oldPassword, byte[] oldSalt, String newPassword, byte[] masterIdentityKey) throws Exception;
	boolean VerifyPassword(String password, SqrlIdentity identity);
	String GetDomainFromUrl(String url) throws Exception;
}
