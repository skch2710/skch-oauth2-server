package com.skch.skch_oauth2_server.util;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AESUtils {

	private static String aesValue;
	
	private static final String AES_PADDING = "AES/GCM/NoPadding";
	private static final String AES = "AES";
	private static final int GCM_IV_LENGTH = 12; // 12 bytes recommended for GCM
	private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag length in bits

	@Value("${app.aes-key}")
	public void aesKey(String aesKey) {
		aesValue = aesKey;
	}
	
	public static String encrypt(String data) {
		String result = "";
		try {
			if (data != null && !data.isBlank()) {
				Cipher cipher = Cipher.getInstance(AES_PADDING);

				// Generate a random IV
				byte[] iv = new byte[GCM_IV_LENGTH];
				SecureRandom secureRandom = new SecureRandom();
				secureRandom.nextBytes(iv);
				GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

				cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(), gcmSpec);
				byte[] encryptedBytes = cipher.doFinal(data.getBytes());

				// Combine IV and encrypted data for output
				ByteBuffer byteBuffer = ByteBuffer.allocate(GCM_IV_LENGTH + encryptedBytes.length);
				byteBuffer.put(iv);
				byteBuffer.put(encryptedBytes);

				result = Base64.getEncoder().encodeToString(byteBuffer.array());
			}
		} catch (Exception e) {
			log.error("Encryption error: {}", e.getMessage(), e);
		}
		return result;
	}

	public static String decrypt(String ciphertext) {
		String result = "";
		try {
			if (ciphertext != null && !ciphertext.isBlank()) {
				Cipher cipher = Cipher.getInstance(AES_PADDING);

				// Decode the base64-encoded input
				byte[] cipherTextBytes = Base64.getDecoder().decode(ciphertext);

				// Extract the IV and the encrypted data
				ByteBuffer byteBuffer = ByteBuffer.wrap(cipherTextBytes);
				byte[] iv = new byte[GCM_IV_LENGTH];
				byteBuffer.get(iv);
				byte[] encryptedBytes = new byte[byteBuffer.remaining()];
				byteBuffer.get(encryptedBytes);

				GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
				cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(), gcmSpec);

				byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
				result = new String(decryptedBytes);
			}
		} catch (Exception e) {
			log.error("Decription error: {}", e.getMessage(), e);
		}
		return result;
	}

	public static SecretKeySpec getSecretKeySpec() {
		SecretKeySpec secretKey = null;
		try {
			byte[] key = Base64.getDecoder().decode(aesValue);
			secretKey = new SecretKeySpec(key, AES);
		} catch (Exception e) {
			log.error("getSecretKeySpec error: {}", e.getMessage(), e);
		}
		return secretKey;
	}
}
