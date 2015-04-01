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
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.CryptoManager;
import es.mityc.crypto.Utils;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.utils.Base64Coder;

public class BlowFishManager implements CryptoManager {

	/** Sistema de traceo. */
	static Log logger = LogFactory.getLog(DESCipherManager.class);

	/** Salt de las contraseñas (@see PKCS#5 standard). */
	private byte[] salt = null;

	/** Iteration de las contraseñas. */
	private int iter = 64;

	/** Clase encargada de las operaciones criptográficas. */
	private Cipher desCipher = null;

	/** Clase encargada de la generación de claves basadas en contraseña. */
	private SecretKeyFactory skfDes = null;

	public BlowFishManager() {
		init(null, 0);
	}

	public BlowFishManager(byte[] salt, int iter) {
		init(salt, iter);
	}
	
	public void feedSeed(byte[] seed) {
		if (seed == null) {
			seed = SecureRandom.getSeed(8);
		}
		for (int i = 0; i < salt.length && i < seed.length; ++i) {
			salt[i] = (byte) (salt[i] & seed[i]);
		}
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
			desCipher = Cipher.getInstance(ConstantsCrypto.BLOWFISH_ALGORITHM);

			skfDes = SecretKeyFactory.getInstance(ConstantsCrypto.BLOWFISH_CFB64_NO_PADDING);
		} catch (NoSuchPaddingException ex) {
			throw new SecurityException(ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new SecurityException(ex);
		}
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
			// Se configura el algoritmo de encriptación (Password-Based Encription, PKCS#5)
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iter);

			// Se calcula la clave
			SecretKey pbeKey = skfDes.generateSecret(new PBEKeySpec(password.toCharArray()));

			// Se inicializa el encriptador con la clave calculada
			desCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

			// Se toma el texto en claro y se convierte a ASCII
			byte[] plainProps = plain.getBytes();

			// Se hace efectiva la encriptación
			byte[] ciphertext = desCipher.doFinal(plainProps);

			return Base64Coder.encode(ciphertext);
		} catch (InvalidKeySpecException ex) {
			throw new SecurityException(ex);
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
			// Se configura el algoritmo de encriptación (Password-Based Encription, PKCS#5)
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iter);

			// Se calcula la clave
			SecretKey pbeKey = skfDes.generateSecret(new PBEKeySpec(password.toCharArray()));

			// Se inicializa el encriptador con la clave calculada
			desCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

			// Se recupera el texto en claro
			byte[] ciphertext = desCipher.doFinal(Base64Coder.decode(cryptedText));

			return ciphertext;
		} catch (InvalidKeySpecException ex) {
			throw new SecurityException(ex);
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
	
	public String getUsedAlgorithmURI() {
		return desCipher.getAlgorithm();
	}

	/**
	 * Main de pruebas
	 */
	public static void main(String[] args) {
		String plain = "TextoEnClaro012456789";
		String pass = "1234567890123456789012345678901234567890";
		DESCipherManager p = new DESCipherManager();
		System.out.println("Texto en claro: " + plain);
		String buffer = Utils.obfuscate(plain);
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
	}
}
