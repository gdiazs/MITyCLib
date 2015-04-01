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
package es.mityc.crypto.symetric;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.CryptoManager;
import es.mityc.crypto.Utils;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.utils.Base64Coder;

public class TripleDESManager implements CryptoManager {

	/** Sistema de traceo. */
	static Log logger = LogFactory.getLog(TripleDESManager.class);

	/** Clase encargada de las operaciones criptográficas. */
	private Cipher tripleDesCipher = null;

	/** Clase encargada de la generación de claves basadas en contraseña. */
	private SecretKeyFactory skf3Des = null;
	
	private SecureRandom random = null;
	private static byte[] salt = null;

	public TripleDESManager() {
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

	private void init() {
		es.mityc.javasign.utils.Utils.addBCProvider();
		try {
			tripleDesCipher = Cipher.getInstance(ConstantsCrypto.TripleDES_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
			skf3Des = SecretKeyFactory.getInstance(ConstantsCrypto.TripleDES_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
		} catch (NoSuchPaddingException ex) {
			throw new SecurityException(ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new SecurityException(ex);
		} catch (NoSuchProviderException ex) {
			throw new SecurityException(ex);
		}
		
		salt = SecureRandom.getSeed(8);
		
		random = new SecureRandom(salt);
	}

	/**
	 * <p>Encripta un fichero con triple DES.</p>
	 * @param plain Texto en claro a encriptar
	 * @param password Contraseña a emplear (al menos 24 bytes)
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectTripleDES(String plain, String password) throws SecurityException {
		if (password == null || "".equals(new String(password).trim()) || plain == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}
		return protectTripleDES(plain.getBytes(), password);
	}

	/**
	 * <p>Encripta un fichero con triple DES.</p>
	 * @param plain Bytes en claro a encriptar
	 * @param password Contraseña a emplear (al menos 24 bytes)
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectTripleDES(byte[] plainBytes, String password) throws SecurityException {
		if (password == null || "".equals(new String(password).trim()) || plainBytes == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		} else if (password.length() < 24) {
			logger.warn("La clave debe tener al menos 24 bytes. Se emplea su valor SHA256 como contraseña.");
			es.mityc.javasign.utils.Utils.addBCProvider();
			try {
				MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA256, ConstantsAPI.PROVIDER_BC_NAME);
				password = new String(hash.digest(password.getBytes()));
			} catch (NoSuchAlgorithmException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
			} catch (NoSuchProviderException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
			}
		}

		try {					
			// Se calcula la clave
			SecretKey desKey = skf3Des.generateSecret(new DESedeKeySpec(password.getBytes()));
			return protectTripleDES(plainBytes, desKey);
		} catch (InvalidKeySpecException ex) {
			throw new SecurityException(ex);
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		}
	}
	
	/**
	 * <p>Encripta un fichero con triple DES.</p>
	 * @param plain Bytes en claro a encriptar
	 * @param password Contraseña a emplear (al menos 24 bytes)
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectTripleDES(byte[] plainBytes, SecretKey key) throws SecurityException {
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Encriptando " + plainBytes.length + " bytes");
			}
			init();
			// Se inicializa el encriptador con la clave calculada
			tripleDesCipher.init(Cipher.ENCRYPT_MODE, key, random);
			// Se hace efectiva la encriptación
			byte[] ciphertext = tripleDesCipher.doFinal(plainBytes);

			return Base64Coder.encode(ciphertext);
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException(ex);
		} finally {
			if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) != null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Eliminando el proveedor BC");
				}
				Security.removeProvider(ConstantsAPI.PROVIDER_BC_NAME);
			}
		}
	}

	/**
	 * <p>Desencripta un fichero en triple DES convirtiéndola a texto plano.</p>
	 * @param cryptedText Texto encriptado
	 * @param password Contraseña a emplear (al menos 24 bytes)
	 * @return Información en claro
	 * @throws SecurityException si se produce un error al desencriptar
	 */
	public byte[] recoverTripleDES(char[] cryptedText, String password) throws SecurityException {
		if (password == null || "".equals(new String(password).trim()) || cryptedText == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		} else if (password.length() < 24) {
			logger.warn("La clave debe tener al menos 24 bytes. Se emplea su valor SHA256 como contraseña.");
			try {
				es.mityc.javasign.utils.Utils.addBCProvider();
				MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA256, ConstantsAPI.PROVIDER_BC_NAME);
				password = new String(hash.digest(password.getBytes()));
			} catch (NoSuchAlgorithmException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
			} catch (NoSuchProviderException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
			}
		}
		try {
			// Se calcula la clave
			SecretKey desKey = skf3Des.generateSecret(new DESedeKeySpec(password.getBytes()));
			return recoverTripleDES(cryptedText, desKey);
		} catch (InvalidKeySpecException ex) {
			throw new SecurityException(ex);
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} finally {
			if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) != null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Eliminando el proveedor BC");
				}
				Security.removeProvider(ConstantsAPI.PROVIDER_BC_NAME);
			}
		}
	}
	
	/**
	 * <p>Desencripta un fichero en triple DES convirtiéndola a texto plano.</p>
	 * @param cryptedText Texto encriptado
	 * @param password Contraseña a emplear (al menos 24 bytes)
	 * @return Información en claro
	 * @throws SecurityException si se produce un error al desencriptar
	 */
	public byte[] recoverTripleDES(char[] cryptedText, SecretKey key) throws SecurityException {
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Recuperando " + cryptedText.length + " bytes");
			}
			init();
			// Se inicializa el encriptador con la clave calculada
			tripleDesCipher.init(Cipher.DECRYPT_MODE, key);//, pbeParamSpec);
			// Se recupera el texto en claro
			return tripleDesCipher.doFinal(Base64Coder.decode(cryptedText));
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException("Contraseña incorrecta", ex);
		} finally {
			if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) != null) {
				if (logger.isDebugEnabled()) {
					logger.debug("Eliminando el proveedor BC");
				}
				Security.removeProvider(ConstantsAPI.PROVIDER_BC_NAME);
			}
		}
	}
	
	/**
	 * <p>Genera una nueva clave.</p>
	 * @return
	 */
	public SecretKey genKey() {
		byte[] randomKey = new byte[30];
		random.nextBytes(randomKey);
		try {
			return skf3Des.generateSecret(new DESedeKeySpec(randomKey));
		} catch (Exception e) {
			logger.error("No se pudo construir la clave aleatoria", e);
			return null;
		}
	}
	
	/**
	 * <p>Recupera una nueva clave triple DES a partir de sus bytes.</p>
	 * @return
	 */
	public SecretKey rebuildKey(byte[] key) {
		try {
			return skf3Des.generateSecret(new DESedeKeySpec(key));
		} catch (Exception e) {
			logger.error("No se pudo reconstruir la clave indicada", e);
			return null;
		}
	}
	
	public String getUsedAlgorithmURI() {
		return "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";//tripleDesCipher.getAlgorithm();
	}

	/**
	 * Main de pruebas
	 */
	public static void main(String[] args) {
		String pass = "1234567890123456789012345678901234567890";
		TripleDESManager p = new TripleDESManager();
		System.out.println("Texto en claro: " + args[0]);
		String buffer = Utils.obfuscate(args[0]);
		System.out.println("Texto ofuscado: " + buffer);
		buffer = Utils.undoObfuscate(buffer.getBytes());
		System.out.println("Texto recuperado: " + buffer);

		char[] bufferChar = p.protectTripleDES(buffer, pass);
		buffer = new String(bufferChar);
		System.out.println("Texto encriptado triple DES: " + buffer);
		buffer = new String(p.recoverTripleDES(bufferChar, pass));
		System.out.println("Texto desencriptado triple DES: " + buffer);

		long start = System.currentTimeMillis();
		buffer = Utils.obfuscate(new String(p.protectTripleDES(buffer, pass)));
		System.out.println("Encriptado y ofuscado triple DES: " + buffer);
		buffer = new String(p.recoverTripleDES(Utils.undoObfuscate(buffer.getBytes()).toCharArray(), pass));
		long time = System.currentTimeMillis() - start;
		System.out.println("Texto recuperado: " + buffer + "\nTiempo consumido (ms): " + time);
	}

}
