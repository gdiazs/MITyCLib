/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
 *
 * Licencia con arreglo a la EUPL, Versión 1.1 o –en cuanto sean aprobadas por la Comisión Europea– versiones posteriores de la EUPL (la Licencia);
 * Solo podrá usarse esta obra si se respeta la Licencia.
 *
 * Puede obtenerse una copia de la Licencia en:
 *
 * http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
 *
 * Salvo cuando lo exija la legislación aplicable o se acuerde por escrito, el programa distribuido con arreglo a la Licencia se distribuye «TAL CUAL»,
 * SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * Véase la Licencia en el idioma concreto que rige los permisos y limitaciones que establece la Licencia.
 */
package es.mityc.crypto.KeyGenerators;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.Utils;
import es.mityc.javasign.ConstantsAPI;

public class KeyAgreementManager {

	public final static int pValue = 47;

	public final static int gValue = 71;

	public static void basicDiffieHellmanExample() throws Exception {
		int bitLength = 512; // 512 bits
		SecureRandom rnd = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(bitLength, rnd);
		BigInteger g = BigInteger.probablePrime(bitLength, rnd);
		DHParameterSpec dhParams = new DHParameterSpec(p, g);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		keyGen.initialize(dhParams, new SecureRandom(rnd.generateSeed(8)));

		
		KeyPair aPair = keyGen.generateKeyPair();
		KeyPair bPair = keyGen.generateKeyPair();

		KeyAgreement aKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		aKeyAgree.init(aPair.getPrivate());
		KeyAgreement bKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		bKeyAgree.init(bPair.getPrivate());

		aKeyAgree.doPhase(bPair.getPublic(), true);
		bKeyAgree.doPhase(aPair.getPublic(), true);
		
		BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
        BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());
		
		if (!k1.equals(k2)) {
        	System.out.println("Las claves generadas no coinciden!");
        } else {
        	System.out.println("El secreto compartido coincide");
        }
		
		MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA1, ConstantsAPI.PROVIDER_BC_NAME);
		System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
		System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));
	}

	public static void ellipticCurveKeyExchangeExample() throws Exception {
		int bitLength = 512; // 512 bits
		SecureRandom rnd = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(bitLength, rnd);
		BigInteger g = BigInteger.probablePrime(bitLength, rnd);

		createSpecificKey(p, g); // ¿pa qué?

		// Con curva elíptica
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ConstantsCrypto.ELIPTIC_CURVE_DH, ConstantsAPI.PROVIDER_BC_NAME);
		EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger(
				"fffffffffffffffffffffffffffffffeffffffffffffffff", 16)), new BigInteger(
						"fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger(
								"fffffffffffffffffffffffffffffffefffffffffffffffc", 16));

		ECParameterSpec ecSpec = new ECParameterSpec(curve, new ECPoint(new BigInteger(
				"fffffffffffffffffffffffffffffffefffffffffffffffc", 16), new BigInteger(
						"fffffffffffffffffffffffffffffffefffffffffffffffc", 16)), new BigInteger(
								"fffffffffffffffffffffffffffffffefffffffffffffffc", 16), 1);
		
		keyGen.initialize(ecSpec, new SecureRandom());

		KeyPair aPair = keyGen.generateKeyPair();
		KeyPair bPair = keyGen.generateKeyPair();

		KeyAgreement aKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.ELIPTIC_CURVE_DH, ConstantsAPI.PROVIDER_BC_NAME);
		aKeyAgree.init(aPair.getPrivate());
		KeyAgreement bKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.ELIPTIC_CURVE_DH, ConstantsAPI.PROVIDER_BC_NAME);
		bKeyAgree.init(bPair.getPrivate());

		aKeyAgree.doPhase(bPair.getPublic(), true);
		bKeyAgree.doPhase(aPair.getPublic(), true);

		MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA1, ConstantsAPI.PROVIDER_BC_NAME);

		BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
        BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

        if (!k1.equals(k2)) {
        	System.out.println("Las claves generadas no coinciden!");
        } else {
        	System.out.println("El secreto compartido coincide");
        }
		
		System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
		System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));
	}
	
	public static void threeActorsKeyExchange() throws Exception {
		// Ejemplo con 3 actores
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		int bitLength = 512; // 512 bits
		SecureRandom rnd = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(bitLength, rnd);
		BigInteger g = BigInteger.probablePrime(bitLength, rnd);
		DHParameterSpec spec = new DHParameterSpec(p, g);
		keyGen.initialize(spec);
		
		KeyPair aPair = keyGen.generateKeyPair();
		KeyPair bPair = keyGen.generateKeyPair();
		KeyPair cPair = keyGen.generateKeyPair();

		KeyAgreement aKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		aKeyAgree.init(aPair.getPrivate());
		KeyAgreement bKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		bKeyAgree.init(bPair.getPrivate());
		KeyAgreement cKeyAgree = KeyAgreement.getInstance(ConstantsCrypto.DIFFIE_HELLMAN_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		cKeyAgree.init(cPair.getPrivate());

		Key ac = aKeyAgree.doPhase(cPair.getPublic(), false);
		Key ba = bKeyAgree.doPhase(aPair.getPublic(), false);
		Key cb = cKeyAgree.doPhase(bPair.getPublic(), false);
		
		aKeyAgree.doPhase(cb, true);
		bKeyAgree.doPhase(ac, true);
		cKeyAgree.doPhase(ba, true);

		BigInteger k1 = new BigInteger(aKeyAgree.generateSecret());
		BigInteger k2 = new BigInteger(bKeyAgree.generateSecret());
        BigInteger k3 = new BigInteger(cKeyAgree.generateSecret());

        if (!k1.equals(k2)) {
        	System.out.println("Las claves a y b generadas no coinciden!");
        } else {
        	System.out.println("El secreto compartido entre a y b coincide");
        }

        if (!k2.equals(k3)) {
        	System.out.println("Las claves b y c generadas no coinciden!");
        } else {
        	System.out.println("El secreto compartido entre b y c coincide");
        }
		
        MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA1, ConstantsAPI.PROVIDER_BC_NAME);
        // Cada uno, en su casa, llega al secreto compartido 
        // empleando su privada y la pública de los demás
		System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
		System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));
		System.out.println(new String(hash.digest(cKeyAgree.generateSecret())));
		
		String plain = "TextoEnClaro123456789";
		SecretKey key = aKeyAgree.generateSecret(ConstantsCrypto.TripleDES_ALGORITHM);
		Cipher tripleDesCipher = Cipher.getInstance(ConstantsCrypto.TripleDES_ALGORITHM);
		// Se inicializa el encriptador con la clave calculada
	    tripleDesCipher.init(Cipher.ENCRYPT_MODE, key);

	    // Se hace efectiva la encriptación
	    byte[] ciphertext = tripleDesCipher.doFinal(plain.getBytes());
	    
	    // Se inicializa el encriptador con la clave calculada del otro actor
	    key = cKeyAgree.generateSecret(ConstantsCrypto.TripleDES_ALGORITHM);
		tripleDesCipher.init(Cipher.DECRYPT_MODE, key);

		// Se recupera el texto en claro
		byte[] restored = tripleDesCipher.doFinal(ciphertext);
		
		System.out.println(new String(restored));
	}

	public static void main(String[] args) throws Exception {
		if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) == null) {
			es.mityc.javasign.utils.Utils.addBCProvider();
		}
		
		basicDiffieHellmanExample();
		
		ellipticCurveKeyExchangeExample();
		
		threeActorsKeyExchange();
	}

	public static void createSpecificKey(BigInteger p, BigInteger g) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");

		if (p != null && g != null) {
			DHParameterSpec param = new DHParameterSpec(p, g);
			kpg.initialize(param);
		} else {
			kpg.initialize(512);
		}

		KeyPair kp = kpg.generateKeyPair();
		KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");

		DHPublicKeySpec kspec = (DHPublicKeySpec) kfactory.getKeySpec(kp.getPublic(), DHPublicKeySpec.class);
	}
}
