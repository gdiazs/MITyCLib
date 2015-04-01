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
package es.mityc.crypto.asymetric;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.CryptoManager;
import es.mityc.crypto.Utils;
import es.mityc.crypto.symetric.TripleDESManager;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.utils.Base64Coder;

public class EllipticCurveManager implements CryptoManager {
	
	/** Sistema de traceo. */
	static Log logger = LogFactory.getLog(EllipticCurveManager.class);
	
	/** Tamaño de clave a generar. */
	private static final int keySize = 4096;
	private static byte[] salt = SecureRandom.getSeed(8);
	
	private Cipher ecCipher = null;
	private SecureRandom random = null;
	
	private TripleDESManager simetricCipher = null;
	
	public EllipticCurveManager() {
		init();
	}
	
	public void feedSeed(byte[] seed) {
		random.nextBytes(salt);
		if (seed != null) {
			for (int i = 0; i < salt.length && i < seed.length; ++i) {
				salt[i] = (byte) (salt[i] & seed[i]);
			}
		}
		random.setSeed(salt);
	}
	
	private void init() throws SecurityException {
		if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) == null) {
			es.mityc.javasign.utils.Utils.addBCProvider();
		}
		try {
			ecCipher = Cipher.getInstance("ECIES", ConstantsAPI.PROVIDER_BC_NAME);
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("No se pudo instanciar el algoritmo EC", e);
		} catch (NoSuchProviderException e) {
			throw new SecurityException("No se encontró el proveedor de BouncyCastle", e);
		} catch (NoSuchPaddingException e) {
			throw new SecurityException("No se pudo inicializar el relleno", e);
		}
		random = new SecureRandom(salt);
	}
	
	/**
	 * <p>Encripta un fichero con RSA.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectEC(String plain, Key key) throws SecurityException {
		if (key == null || plain == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}

		try {
			ecCipher.init(Cipher.ENCRYPT_MODE, key, random);
			byte[] cipherText = ecCipher.doFinal(plain.getBytes());

			return Base64Coder.encode(cipherText);
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException(ex);
		}
	}
	
	/**
	 * <p>Desencripta un fichero en RSA convirtiéndolo en texto plano.</p>
	 * @param cryptedText Texto encriptado a recuperar
	 * @param key Clave asimetrica a emplear
	 * @return Información en claro
	 * @throws SecurityException en caso de que se produzca un error al recuperar el texto
	 */
	public byte[] recoverEC(char[] cryptedText, Key key) throws SecurityException {
		if (key == null || cryptedText == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}
		try {
			// Se inicializa el encriptador con la clave calculada
			ecCipher.init(Cipher.DECRYPT_MODE, key);

			// Se recupera el texto en claro
			byte[] ciphertext = ecCipher.doFinal(Base64Coder.decode(cryptedText));

			return ciphertext;
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException("Clave incorrecta", ex);
		}
	}
	
	/**
	 * <p>Genera y protege mediante tripleDES un nuevo par de claves asimetricas de curva eliptica.</p>
	 * @param password Contraseña con la cual se protege simétricamente el par de claves asimétrico
	 * @return
	 */
	public String genNewECKeys(String password) {
		try {
			// Se genera el nuevo par de claves de curva eliptica
			//KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", ConstantsCrypto.PROVIDER_BC_NAME);
			
			ECCurve curva = new ECCurve.Fp(
					new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"),
					new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
					new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16));

			ECParameterSpec ecSpec = new ECParameterSpec(
					curva,
					curva.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")),
					new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"));

			KeyPairGenerator generator = KeyPairGenerator.getInstance("ECIES", ConstantsAPI.PROVIDER_BC_NAME);			
			
			generator.initialize(192, random);//ecSpec, random);
			KeyPair newKeys = generator.generateKeyPair();
			
			/****/
			try {			
				PrivateKey privateKey=newKeys.getPrivate();
				PublicKey publicaKey=newKeys.getPublic();
				
				System.out.println("Clave privada " + privateKey.toString());
				System.out.println("Clave publica " + publicaKey.toString());
				
				newKeys = generator.generateKeyPair();
				
				PrivateKey priKey= newKeys.getPrivate();
				PublicKey pubKey= newKeys.getPublic();

				Cipher cifrador = Cipher.getInstance("ECIES",ConstantsAPI.PROVIDER_BC_NAME);
				
				IEKeySpec   c1Key = new IEKeySpec(privateKey, pubKey);
				IEKeySpec   c2Key = new IEKeySpec(priKey, publicaKey);

				byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
				byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
				 
				IESParameterSpec param = new IESParameterSpec(d, e, 128);

				cifrador.init(Cipher.ENCRYPT_MODE, c1Key, param);
				byte[] mensajeCifrado=cifrador.doFinal("123456".getBytes());
				System.out.println("Mensaje Cifrado: " + mensajeCifrado);
				
				cifrador.init(Cipher.DECRYPT_MODE, c2Key, param);
				byte[] mensajeRecuperado=cifrador.doFinal(mensajeCifrado);
				System.out.println("Mensaje Recuperado: " + new String(mensajeRecuperado));
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			/****/
						
			// Se obtiene la codificación del par de claves por separado
			byte[] pbcBuffer = newKeys.getPublic().getEncoded();
			byte[] pvtBuffer = newKeys.getPrivate().getEncoded();
			
			// Se serializa el par de claves junto al tamaño de clave pública
			int totalSize = pbcBuffer.length + pvtBuffer.length + 4;
			byte[] pairData = new byte[totalSize];
			
			char[] pubSize = String.valueOf(pbcBuffer.length).toCharArray();

			// Los primeros 4 bytes se reservan para almacenar el tamaño de clave
		    for (int i = 0; i < pubSize.length; i++) {
		       pairData[i] = (byte)pubSize[i];
		    }
						
			for (int i = 0; i < pbcBuffer.length; ++i) {
				pairData[(i + 4)] = pbcBuffer[(i)];
			}
			for (int i = pbcBuffer.length + 4; i < totalSize; ++i) {
				pairData[i] = pvtBuffer[(i-(pbcBuffer.length + 4))];
			}
			
			if (simetricCipher == null) {
				simetricCipher = new TripleDESManager();
			}
			
			char[] encPairChar = simetricCipher.protectTripleDES(pairData, password); 
			
			return new String(encPairChar);
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException(e);
		} catch (NoSuchProviderException e) {
			throw new SecurityException(e);
		}
	}
	
	/**
	 * <p>Recupera mediante</p>
	 * @param encPair
	 * @param password
	 * @return
	 */
	public KeyPair unprotectKeyPair(String encPair, String password) throws SecurityException {
		return unprotectKeyPair(encPair.toCharArray(), password);
	}
	
	public KeyPair unprotectKeyPair(char[] encPairChar, String password) throws SecurityException {
		if (simetricCipher == null) {
			simetricCipher = new TripleDESManager();
		}
		// Se recupera el par encriptado
		byte[] pair = simetricCipher.recoverTripleDES(encPairChar, password);
		
		// Se extrae el tamaño de la clave pública de los primeros 4 bytes
		int pubKeySize = 0;
		int cifra = 0;
		for (int i = 0; i < 4; i++) {
			try {
				cifra = Integer.valueOf(String.valueOf((char)pair[i]));
				if (cifra >= 0 && cifra <= 9)
					pubKeySize = (pubKeySize * (10)) + cifra;
			} catch (NumberFormatException e) {
				break;
			}
		}
		
		// Se recupera el par de claves codificado
		byte[] publicKeyData = new byte[pubKeySize];
		byte[] privateKeyData = new byte[pair.length - pubKeySize - 4];
		
		for (int i = 4; i < pubKeySize + 4; ++i) {
			publicKeyData[(i - 4)] = pair[i];
		}
		for (int i = pubKeySize + 4; i < pair.length; ++i) {
			privateKeyData[(i - (pubKeySize + 4))] = pair[i];
		}
		
		// Se reconstruye el par de claves
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(ConstantsCrypto.RSA_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
	        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);
			
			return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException(e);
		} catch (InvalidKeySpecException e) {
			throw new SecurityException(e);
		} catch (NoSuchProviderException e) {
			throw new SecurityException(e);
		}
	}
	
	public String getUsedAlgorithmURI() {
		return ecCipher.getAlgorithm();
	}
	
	/**
	 * Main de pruebas
	 */
	public static void main(String[] args) {
		String plain = "TextoEnClaro0123456789";
		EllipticCurveManager p = new EllipticCurveManager();
		// Se crea un nuevo par de claves
		System.out.println("Se solicita el cálculo de un nuevo par de claves asimétricas de " + keySize + " bits");
		Long start = System.currentTimeMillis();
		String protectedPair = p.genNewECKeys("123456789012345678901234");
		KeyPair pair = p.unprotectKeyPair(protectedPair, "123456789012345678901234");
		Long time = System.currentTimeMillis() - start;
		System.out.println("Claves obtenidas. " + "Tiempo consumido (ms): " + time + ". Comienzan las pruebas de encriptación...");
		// Se comienza con la batería de pruebas
		System.out.println("Texto en claro: " + plain);
		String buffer = plain;
		char[] bufferChar = p.protectEC(buffer, pair.getPrivate()); //p.prvKey);
		buffer = new String(bufferChar);
		System.out.println("Texto encriptado RSA con privada: " + buffer);
		buffer = new String(p.recoverEC(bufferChar, pair.getPublic()));//p.pubKey));
		System.out.println("Texto desencriptado RSA con pública: " + buffer);
		// Batería de pruebas con ofuscación
		start = System.currentTimeMillis();
		buffer = Utils.obfuscate(new String(p.protectEC(buffer, pair.getPublic())));
		System.out.println("Encriptado RSA con pública y ofuscado: " + buffer);
		buffer = new String(p.recoverEC(Utils.undoObfuscate(buffer.getBytes()).toCharArray(), pair.getPrivate()));
		time = System.currentTimeMillis() - start;
		System.out.println("Texto recuperado con privada: " + buffer + "\nTiempo consumido (ms): " + time);
	}
}