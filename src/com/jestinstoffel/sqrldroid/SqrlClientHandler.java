package com.jestinstoffel.sqrldroid;

public interface SqrlClientHandler {
	byte[] calculateMasterKey(byte[] masterIdentityKey, String password, byte[] salt) throws Exception;
	byte[] calculateMasterIdentityKey(byte[] masterKey, String password, byte[] salt) throws Exception;
	SqrlData getSqrlDataForLogin(byte[] masterKey, String url) throws Exception;
	SqrlData getSqrlDataForLogin(byte[] masterIdentityKey, String password, byte[] salt, String url) throws Exception;
	SqrlData getSqrlDataForLogin(SqrlIdentity identity, String password, String url) throws Exception;
	SqrlIdentity createIdentity(String password, byte[] entropy) throws Exception;
	SqrlIdentity changePassword(String oldPassword, byte[] oldSalt, String newPassword, byte[] masterIdentityKey) throws Exception;
	boolean verifyPassword(String password, SqrlIdentity identity);
	String getDomainFromUrl(String url) throws Exception;
}
