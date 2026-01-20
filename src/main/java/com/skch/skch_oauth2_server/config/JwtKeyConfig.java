package com.skch.skch_oauth2_server.config;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtKeyConfig {
	
	@Value("${security.oauth2.jwt.private-key}")
	private String PRIVATE_KEY;
	
	@Value("${security.oauth2.jwt.public-key}")
	private String PUBLIC_KEY;
	
	@Value("${security.oauth2.kid}")
	private String KID;

    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {
		RSAPublicKey publicKey = loadPublicKey();
		RSAPrivateKey privateKey = loadPrivateKey();
		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
				.keyID(KID).build();
		return new ImmutableJWKSet<>(new JWKSet(rsaKey));
	}

	private RSAPrivateKey loadPrivateKey() throws Exception {
		byte[] decoded = Base64.getDecoder().decode(PRIVATE_KEY);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
	}

	private RSAPublicKey loadPublicKey() throws Exception {
		byte[] decoded = Base64.getDecoder().decode(PUBLIC_KEY);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
	}
	
//	public static void main(String[] args) throws Exception {
//		printPemKeys();
//		System.out.println(UUID.randomUUID().toString());
//	}
//
//	private static void printPemKeys() throws Exception {
//		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//        generator.initialize(2048);
//        KeyPair keyPair = generator.generateKeyPair();
//        
//		// ===== PRIVATE KEY (PKCS#8) =====
//		String privateKeyPem = Base64.getMimeEncoder(64, new byte[] { '\n' })
//				.encodeToString(keyPair.getPrivate().getEncoded());
//		// ===== PUBLIC KEY (X.509) =====
//		String publicKeyPem = Base64.getMimeEncoder(64, new byte[] { '\n' })
//				.encodeToString(keyPair.getPublic().getEncoded());
//		System.out.println("\n========== PRIVATE KEY ==========\n");
//		System.out.println(privateKeyPem);
//		System.out.println("\n========== PUBLIC KEY ==========\n");
//		System.out.println(publicKeyPem);
//	}
}
