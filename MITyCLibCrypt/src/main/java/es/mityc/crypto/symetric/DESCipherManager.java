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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
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
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.CryptoManager;
import es.mityc.crypto.Utils;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.utils.Base64Coder;

public class DESCipherManager implements CryptoManager {
	
	/** Sistema de traceo. */
	static Log logger = LogFactory.getLog(DESCipherManager.class);
	
	/** Generador de números aleatorios. */
	private SecureRandom random = null;
	
	/** Salt de las contraseñas PBE (@see PKCS#5 standard). */
	private byte[] salt = null;
	
	/** Iteration de las contraseñas PBE. */
	private int iter = 64;
	
	/** Clase encargada de las operaciones criptográficas. */
	private Cipher desCipher = null;
	
	/** Clase encargada de la generación de claves basadas en contraseña. */
	private SecretKeyFactory skfDes = null;
	
	public DESCipherManager() {
		init(null, 0);
	}
	
	public DESCipherManager(byte[] salt, int iter) {
		init(salt, iter);
	}
	
	public void feedSeed(byte[] seed) {
		if (seed == null) {
			seed = SecureRandom.getSeed(8);
		}
		for (int i = 0; i < salt.length && i < seed.length; ++i) {
			salt[i] = (byte) (salt[i] & seed[i]);
		}
		random.setSeed(salt);
	}
	
	private void init(byte[] salt, int iter) {
		// Se inicializa objeto de seguridad para proteger la configuración
		if (salt != null) {
			this.salt = salt;
		} else {
			this.salt = SecureRandom.getSeed(8);
		}
		
		if (iter != 0) {
			this.iter = iter;
		}
		
		// Se instancia el proveedor BouncyCastle
		if (Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME) == null) {
			es.mityc.javasign.utils.Utils.addBCProvider();
		}
		
		try {
			desCipher = Cipher.getInstance(ConstantsCrypto.PBE_DES_ALGORITHM);
			
			skfDes = SecretKeyFactory.getInstance(ConstantsCrypto.PBE_DES_ALGORITHM);
		} catch (NoSuchPaddingException ex) {
			throw new SecurityException(ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new SecurityException(ex);
		}
		random = new SecureRandom(salt);
	}
	
	/**
	 * <p>Encripta un fichero con DES.</p>
	 * @param plain Texto en claro a encriptar
	 * @param password Contraseña a emplear (8 bytes mínimo)
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectPBEandDES(String plain, String password) throws SecurityException {
		if (password == null || "".equals(new String(password).trim()) || plain == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		} else if (password.length() < 8) {
			logger.warn("La clave debe tener al menos 8 bytes. Se emplea su valor SHA1 como contraseña.");
			try {
				MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA1, ConstantsAPI.PROVIDER_BC_NAME);
				password = new String(hash.digest(password.getBytes()));
			} catch (NoSuchAlgorithmException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
			} catch (NoSuchProviderException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
				
			}
		}
		try {					
			// Se calcula la clave
		    SecretKey pbeKey = skfDes.generateSecret(new PBEKeySpec(password.toCharArray()));
		    
		    // Se toma el texto en claro y se convierte a ASCII
		    byte[] plainProps = plain.getBytes();
		    
		    return protectDES(plainProps, pbeKey);
		} catch (InvalidKeySpecException ex) {
			throw new SecurityException(ex);
		}
	}
	
	/**
	 * <p>Desencripta un fichero en DES convirtiéndolo en texto plano.</p>
	 * @param cryptedText Texto encriptado a recuperar
	 * @param password Contraseña a emplear
	 * @return Información en claro
	 * @throws SecurityException en caso de que se produzca un error al recuperar el texto
	 */
	public byte[] recoverPBEandDES(char[] cryptedText, String password) throws SecurityException {
		if (password == null || "".equals(new String(password).trim()) || cryptedText == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		} else if (password.length() < 8) {
			logger.warn("La clave debe tener al menos 8 bytes. Se emplea su valor SHA1 como contraseña.");
			try {
				MessageDigest hash = MessageDigest.getInstance(ConstantsCrypto.DIGEST_ALG_SHA1, ConstantsAPI.PROVIDER_BC_NAME);
				password = new String(hash.digest(password.getBytes()));
			} catch (NoSuchAlgorithmException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
			} catch (NoSuchProviderException e) {
				throw new SecurityException("Error al calcular el Digest de la contraseña", e);
				
			}
		}
		try {
			// Se calcula la clave
			SecretKey pbeKey = skfDes.generateSecret(new PBEKeySpec(password.toCharArray()));

			return recoverDES(cryptedText, pbeKey);
		} catch (InvalidKeySpecException ex) {
			throw new SecurityException(ex);
		}
	}
	
	/**
	 * <p>Encripta un fichero con DES.</p>
	 * @param plain Texto en claro a encriptar
	 * @param sk Clave DES a emplear
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectDES(byte[] plain, SecretKey sk) throws SecurityException {
		try {
			// Se configura el algoritmo de encriptación (Password-Based Encription, PKCS#5)
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iter);

			// Se inicializa el encriptador con la clave calculada
			desCipher.init(Cipher.ENCRYPT_MODE, sk, pbeParamSpec);

			// Se hace efectiva la encriptación
			byte[] ciphertext = desCipher.doFinal(plain);

			return Base64Coder.encode(ciphertext);
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (InvalidAlgorithmParameterException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException(ex);
		}
	}
	
	/**
	 * <p>Desencripta un fichero en DES convirtiéndolo en texto plano.</p>
	 * @param cryptedText Texto encriptado a recuperar
	 * @param sk Clave a emplear
	 * @return Información en claro
	 * @throws SecurityException en caso de que se produzca un error al recuperar el texto
	 */
	public byte[] recoverDES(char[] cryptedText, SecretKey sk) throws SecurityException {
		try {
			// Se configura el algoritmo de encriptación (Password-Based Encription, PKCS#5)
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iter);

			// Se inicializa el encriptador con la clave calculada
			desCipher.init(Cipher.DECRYPT_MODE, sk, pbeParamSpec);

			return desCipher.doFinal(Base64Coder.decode(cryptedText));
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (InvalidAlgorithmParameterException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException("Contraseña incorrecta", ex);
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
			return skfDes.generateSecret(new DESKeySpec(randomKey));
		} catch (Exception e) {
			logger.error("No se pudo construir la clave aleatoria", e);
			return null;
		}
	}
	
	/**
	 * <p>Recupera una nueva clave DES a partir de sus bytes.</p>
	 * @return
	 */
	public SecretKey rebuildKey(byte[] key) {
		try {
			return skfDes.generateSecret(new DESKeySpec(key));
		} catch (Exception e) {
			logger.error("No se pudo reconstruir la clave indicada", e);
			return null;
		}
	}
	
	public String getUsedAlgorithmURI() {
		return "http://www.w3.org/2001/04/xmlenc#des-cbc";//desCipher.getAlgorithm();
	}
	
	/**
	 * Main de pruebas
	 */
	public static void main(String[] args) {
		String pass = "1234567890123456789012345678901234567890";
		DESCipherManager p = new DESCipherManager();
		System.out.println("Texto en claro: " + args[0]);
		String buffer = Utils.obfuscate(args[0]);
		System.out.println("Texto ofuscado: " + buffer);
		buffer = Utils.undoObfuscate(buffer.getBytes());
		System.out.println("Texto recuperado: " + buffer);
		char[] bufferChar = p.protectPBEandDES(buffer, pass);
		buffer = new String(bufferChar);
		System.out.println("Texto encriptado PBEandDES: " + buffer);
		buffer = new String(p.recoverPBEandDES(bufferChar, pass));
		System.out.println("Texto desencriptado PBEandDES: " + buffer);
		
		Long start = System.currentTimeMillis();
		buffer = Utils.obfuscate(new String(p.protectPBEandDES(buffer, pass)));
		System.out.println("Encriptado PBEandDES y ofuscado: " + buffer);
		buffer = new String(p.recoverPBEandDES(Utils.undoObfuscate(buffer.getBytes()).toCharArray(), pass));
		Long time = System.currentTimeMillis() - start;
		System.out.println("Texto recuperado: " + buffer + "\nTiempo consumido (ms): " + time);
		
		// Calculo para SRX
		try {
			SecretKeyFactory skfDes = SecretKeyFactory.getInstance(ConstantsCrypto.PBE_DES_ALGORITHM);
			SecretKey pbeKey = skfDes.generateSecret(new PBEKeySpec(pass.toCharArray()));
			
			BufferedReader br = new BufferedReader(new InputStreamReader(p.getClass().getResourceAsStream("/prueba.pdf")));
			StringBuffer sb = new StringBuffer();
			String line = br.readLine();
			while(line != null) {
				sb.append(line);
				line = br.readLine();
			}
			byte[] aEnc = sb.toString().getBytes();
			bufferChar = p.protectDES(aEnc, pbeKey);
			start = System.currentTimeMillis();
			buffer = new String(p.recoverDES(bufferChar, pbeKey));
			time = System.currentTimeMillis() - start;
			System.out.println("Tiempo consumido (ms): " + time);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
