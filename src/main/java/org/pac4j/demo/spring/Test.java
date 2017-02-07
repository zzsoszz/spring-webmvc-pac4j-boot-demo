package org.pac4j.demo.spring;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.jwt.config.encryption.ECEncryptionConfiguration;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.RSASignatureConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.oauth.profile.facebook.FacebookProfile;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;

public class Test {
	public static void main(String[] args) throws NoSuchAlgorithmException {
//		
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//		kpg.initialize(2048);
//		
//		SecureRandom random = new SecureRandom();
//		byte[] sharedSecret = new byte[32];
//		random.nextBytes(sharedSecret);
//		
		
		String SECRET="12345678901234567890123456789012";
		byte[] SECRETb="12345678901234567890123456789012".getBytes();
		System.out.println(SECRETb.length);
		JwtGenerator<FacebookProfile> generator = new JwtGenerator<FacebookProfile>(new SecretSignatureConfiguration(SECRET), new SecretEncryptionConfiguration(SECRET));
		FacebookProfile facebookProfile=new FacebookProfile();
		String token = generator.generate(facebookProfile);
		System.out.println(token);
//		
//		JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
//
//		jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration(KEY2));
//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//		KeyPair rsaKeyPair = keyGen.generateKeyPair();
//		jwtAuthenticator.addSignatureConfiguration(new RSASignatureConfiguration(rsaKeyPair));
//		
//		jwtAuthenticator.addEncryptionConfiguration(new SecretEncryptionConfiguration(SECRET));
//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
//		KeyPair ecKeyPair = keyGen.generateKeyPair();
//		ECEncryptionConfiguration encConfig = new ECEncryptionConfiguration(ecKeyPair);
//		encConfig.setAlgorithm(JWEAlgorithm.ECDH_ES_A128KW);
//		encConfig.setMethod(EncryptionMethod.A192CBC_HS384);
//		jwtAuthenticator.addEncryptionConfiguration(encConfig);
//
//		jwtAuthenticator.validate(new TokenCredentials(token, "myclient"));
	}
}
