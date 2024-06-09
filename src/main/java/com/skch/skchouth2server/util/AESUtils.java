package com.skch.skchouth2server.util;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AESUtils {

	private static final String AES_PADDING = "AES/ECB/PKCS5Padding";
	private static final String AES = "AES";
	
	private static String aesKey;
	
	@Value("${app.aes-key}")
	public void setAesKey(String aesKey) {
		AESUtils.aesKey = aesKey;
	}

	public static String encrypt(String data) {
		String result = "";
		try {
			if (data != null && !data.isBlank()) {
				Cipher cipher = Cipher.getInstance(AES_PADDING);
				cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec());
				byte[] encryptedBytes = cipher.doFinal(data.getBytes());
				result = Base64.getEncoder().encodeToString(encryptedBytes);
			}
		} catch (Exception e) {
			log.error("Encryption error: " + e);
		}
		return result;
	}

	public static String decrypt(String ciphertext) {
		String result = "";
		try {
			if (ciphertext != null && !ciphertext.isBlank()) {
				Cipher cipher = Cipher.getInstance(AES_PADDING);
				cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec());
				byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
				result = new String(decryptedBytes);
			}
		} catch (Exception e) {
			log.error("Decryption error: " + e);
		}
		return result;
	}

	public static SecretKeySpec getSecretKeySpec() {
		SecretKeySpec secretKey = null;
		try {
			byte[] key = Base64.getDecoder().decode(aesKey);
			secretKey = new SecretKeySpec(key, AES);
		} catch (Exception e) {
			log.error("SecretKeySpec error: " + e);
		}
		return secretKey;
	}
}
