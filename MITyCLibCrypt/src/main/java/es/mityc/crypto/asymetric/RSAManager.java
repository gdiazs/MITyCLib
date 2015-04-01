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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
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

import es.mityc.crypto.ConstantsCrypto;
import es.mityc.crypto.CryptoManager;
import es.mityc.crypto.Utils;
import es.mityc.crypto.symetric.TripleDESManager;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.utils.Base64Coder;

public class RSAManager implements CryptoManager {
	
	/** Sistema de traceo. */
	static Log logger = LogFactory.getLog(RSAManager.class);
	
	/** Tamaño de clave a generar. */
	private static final int keySize = 1024;
	private static final byte[] salt = SecureRandom.getSeed(8);
	
	private Cipher rsaCipher = null;
	private SecureRandom random = null;
	
	private TripleDESManager simetricCipher = null;	
	
	public static final String RSA_OAEP_KEY = "RSA/None/OAEPWithSHA1AndMGF1Padding";
	public static final String RSA_NONE = "RSA/None/NoPadding";
	public static final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";
	public static final String RSA = "RSA";
	
	private String usedAlgorithm = RSA_OAEP_KEY;
	
	public RSAManager() {
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
			rsaCipher = Cipher.getInstance(RSA_OAEP_KEY, ConstantsAPI.PROVIDER_BC_NAME);
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("No se pudo instanciar el algoritmo RSA", e);
		} catch (NoSuchProviderException e) {
			throw new SecurityException("No se encontró el proveedor de BouncyCastle", e);
		} catch (NoSuchPaddingException e) {
			throw new SecurityException("No se pudo inicializar el relleno", e);
		}
		random = new SecureRandom(salt);
	}
	
	/**
	 * <p>Encripta un fichero con RSA. La implementación de BC impide encriptar bloques de tamaño mayor al tamaño de clave.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectRSA(String plain, Key key) throws SecurityException {
		return protectRSA(plain.getBytes(), key);
	}
	
	/**
	 * <p>Encripta un fichero con RSA. La implementación de BC impide encriptar bloques de tamaño mayor al tamaño de clave.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @param Proveedor criptográfico a utilizar
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectRSA(String plain, Key key, Provider provider) throws SecurityException {
		return protectRSA(plain.getBytes(), key, provider);
	}
	
	/**
	 * <p>Encripta un fichero con RSA. La implementación de BC impide encriptar bloques de tamaño mayor al tamaño de clave.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectRSA(final byte[] plain, final Key key) throws SecurityException {
		if (key == null || plain == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}

		try {
			rsaCipher.init(Cipher.ENCRYPT_MODE, key, random);
			byte[] cipherText = rsaCipher.doFinal(plain);

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
	 * <p>Encripta un fichero con RSA. La implementación de BC impide encriptar bloques de tamaño mayor al tamaño de clave.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @param alg Id del algoritmo a emplear. Véase RSAManager.RSA_OAEP_KEY...
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectRSA(final byte[] plain, final Key key, String alg) throws SecurityException {
		return protectRSA(plain, key,alg,null);
	}
	/**
	 * <p>Encripta un fichero con RSA. La implementación de BC impide encriptar bloques de tamaño mayor al tamaño de clave.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @param alg Id del algoritmo a emplear. Véase RSAManager.RSA_OAEP_KEY...
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectRSA(final byte[] plain, final Key key, String alg,Provider provider) throws SecurityException {
		if (key == null || plain == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}

		if ( provider == null)
			provider = Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME);

		Cipher cipher = null;
		try {
			usedAlgorithm = alg;
			cipher = Cipher.getInstance(usedAlgorithm, provider.getName());
			if (logger.isDebugEnabled()) {
				logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + cipher.getProvider().getName());
			}
			cipher.init(Cipher.ENCRYPT_MODE, key, random);
			byte[] cipherText = cipher.doFinal(plain);

			return Base64Coder.encode(cipherText);
		} catch (Exception ex) {
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
	 * <p>Encripta un fichero con RSA. La implementación de BC impide encriptar bloques de tamaño mayor al tamaño de clave.</p>
	 * @param plain Texto en claro a encriptar
	 * @param key Clave asimetrica a emplear
	 * @param Proveedor criptográfico a utilizar
	 * @return resultado encriptado
	 * @throws SecurityException Lanzada cuando se produce algún error al encriptar el texto
	 */
	public char[] protectRSA(final byte[] plain, final Key key, final Provider provider) throws SecurityException {
		if (key == null || plain == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}
		
		// Se inicializa el encriptador con la clave calculada
		Cipher cipher = null;
		usedAlgorithm = RSA_OAEP_KEY;
		try {
			if (provider != null) {
				Service s = provider.getService("Cipher", usedAlgorithm);
				if (s == null) {
					logger.error("No se pudo encontrar el servicio Cipher.RSA en " + provider.getName());
					usedAlgorithm = "RSA";
					if (logger.isTraceEnabled() && provider.getServices() != null) {
						logger.trace("Servicios disponibles --> ");
						Object[] ser = provider.getServices().toArray();
						for (int i = 0; i < ser.length; ++i) {
							logger.trace("Algoritmo disponible: " + ((Service)ser[i]).getAlgorithm());
						}
					}
				}
				if (logger.isDebugEnabled()) {
					logger.debug("Proveedor: " + provider.getInfo());
					logger.debug("Algoritmo a emplear: " + usedAlgorithm);
				}
				cipher = Cipher.getInstance(usedAlgorithm, provider);
			} else {
				cipher = Cipher.getInstance(usedAlgorithm);
			}

			cipher.init(Cipher.ENCRYPT_MODE, key, random);
			byte[] cipherText = cipher.doFinal(plain);

			return Base64Coder.encode(cipherText);
		} catch (InvalidKeyException ex) {
			try {
				if (logger.isDebugEnabled()) {
					logger.error(ex);
					logger.debug("Reintento con configuración por defecto: ");
				}
				
				usedAlgorithm = RSA_ECB_PKCS1;
				cipher = Cipher.getInstance(usedAlgorithm, ConstantsAPI.PROVIDER_BC_NAME);
				if (logger.isDebugEnabled()) {
					logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + cipher.getProvider().getName());
				}
				cipher.init(Cipher.ENCRYPT_MODE, key, random);
				byte[] cipherText = cipher.doFinal(plain);

				return Base64Coder.encode(cipherText);
			} catch (Exception e) {
				if (logger.isDebugEnabled()) {
					logger.debug("Error al encriptar", e);
				}
				throw new SecurityException(ex);
			}
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException(ex);
		} catch (NoSuchAlgorithmException e) {
			try {
				if (logger.isDebugEnabled()) {
					logger.error(e);
					logger.debug("NoSuchAlgorithmException. Reintento con configuración por defecto: ");
				}
				usedAlgorithm = RSA_ECB_PKCS1;
				cipher = Cipher.getInstance(usedAlgorithm, ConstantsAPI.PROVIDER_BC_NAME);
				cipher.init(Cipher.ENCRYPT_MODE, key, random);
				byte[] cipherText = cipher.doFinal(plain);

				return Base64Coder.encode(cipherText);
			} catch (Exception e2) {
				if (logger.isDebugEnabled()) {
					logger.debug("No se encontró el algoritmo", e2);
				}
				throw new SecurityException("No se detectó el algoritmo RSA", e);
			}
		} catch (NoSuchPaddingException e) {
			throw new SecurityException(e);
		} finally {
			if (provider != null && Security.getProvider(provider.getName()) != null) {
        		Security.removeProvider(provider.getName());
        	}
		}
	}
	
	/**
	 * <p>Desencripta un fichero en RSA convirtiéndolo en texto plano.</p>
	 * @param cryptedText Texto encriptado a recuperar
	 * @param key Clave asimetrica a emplear
	 * @return Información en claro
	 * @throws SecurityException en caso de que se produzca un error al recuperar el texto
	 */
	public byte[] recoverRSA(final char[] cryptedText, final Key key) throws SecurityException {
		if (key == null || cryptedText == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}
		try {
			// Se inicializa el encriptador con la clave calculada
			rsaCipher.init(Cipher.DECRYPT_MODE, key);

			// Se recupera el texto en claro
			byte[] ciphertext = rsaCipher.doFinal(Base64Coder.decode(cryptedText));

			return ciphertext;
		} catch (InvalidKeyException ex) {
			throw new SecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new SecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new SecurityException("Clave incorrecta", ex);
		} catch (IllegalArgumentException ex) {			
			throw new SecurityException("Clave incorrecta", ex);
		}
	}
	
	/**
	 * <p>Desencripta un fichero en RSA convirtiéndolo en texto plano.</p>
	 * @param cryptedText Texto encriptado a recuperar
	 * @param key Clave asimetrica a emplear
	 * @param URI del algoritmo empleado
	 * @return Información en claro
	 * @throws SecurityException en caso de que se produzca un error al recuperar el texto
	 */
	public byte[] recoverRSA(final char[] cryptedText, final IPKStoreManager storeManager, final X509Certificate cert, String algoritmURI) throws SecurityException {
		return recoverRSA(cryptedText,storeManager,cert,algoritmURI,null);
	}
	/**
	 * <p>Desencripta un fichero en RSA convirtiéndolo en texto plano.</p>
	 * @param cryptedText Texto encriptado a recuperar
	 * @param key Clave asimetrica a emplear
	 * @param URI del algoritmo empleado
	 * @return Información en claro
	 * @throws SecurityException en caso de que se produzca un error al recuperar el texto
	 */
	public byte[] recoverRSA(final char[] cryptedText, final IPKStoreManager storeManager, final X509Certificate cert, String algoritmURI,Provider provider) throws SecurityException {
		if (storeManager == null || cryptedText == null || cert == null) {
			throw new SecurityException("Faltan parámetros de entrada");	
		}
		if ( provider == null )
			provider = Security.getProvider(ConstantsAPI.PROVIDER_BC_NAME);
		PrivateKey privateKey = null;
		try {						
			if (provider != null && Security.getProvider(provider.getName()) == null) {
        		Security.addProvider(provider);
        		if (logger.isDebugEnabled()) {
        			if (Security.getProvider(provider.getName()) == null) {
        				logger.debug("No se ha insertado el proveedor");	
        			} else {
        				logger.debug("Proveedor insertado correctamente");		
        			}
        		}
        	}
			
			privateKey = storeManager.getPrivateKey(cert);
			
			if (logger.isTraceEnabled()) {
				Provider[] provs = Security.getProviders();
				//Provider p =null;
				if (provs != null) {
					logger.trace("\n*** Proveedores disponibles --> ");
					for (int i = 0; i < provs.length; ++i) {
						logger.trace(provs[i].getName());
					}
				}
				if (provider != null && provider.getServices() != null) {
					logger.trace("\n*** Servicios disponibles en " + provider.getName() + " --> ");
					Object[] ser = provider.getServices().toArray();
					for (int i = 0; i < ser.length; ++i) {
						logger.trace(((Service)ser[i]).getAlgorithm());
					}
				}
				if (privateKey != null) {
					logger.trace("Algoritmo de la clave privada --> " + privateKey.getAlgorithm());
					logger.trace("Formato de la clave privada --> " + privateKey.getFormat());
				}
			}
			if (algoritmURI != null) {
				usedAlgorithm = algoritmURI;
			} else {
				usedAlgorithm = RSA_OAEP_KEY;
			}
			// Se inicializa el encriptador con la clave calculada
			Cipher cipher = null;
			if (provider != null) {
				cipher = Cipher.getInstance(usedAlgorithm, provider);
				if (logger.isDebugEnabled()) {
					logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + provider);
				}
			} else {
				if (logger.isDebugEnabled()) {
					logger.debug("Empleando el algoritmo " + usedAlgorithm + " con la lista de proveedores");
				}
				cipher = Cipher.getInstance(usedAlgorithm);
			}

			byte[] ciphertext = null;
			ciphertext = decryptText(cryptedText, provider, privateKey, cipher);

			return ciphertext;
		} catch (Exception ex) {
			if (logger.isDebugEnabled())
				logger.debug("Se produjo un error al desencriptar: " + ex.getMessage(), ex);
			try { // Se busca el algoritmo en cualquier proceedor de entre los disponibles (por orden)
				usedAlgorithm = RSA_OAEP_KEY;
				Cipher cipher = Cipher.getInstance(usedAlgorithm);
				if (logger.isDebugEnabled()) {
					logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + cipher.getProvider().getName());
				}
				
				// Se recupera el texto en claro
				byte[] ciphertext = decryptText(cryptedText, provider, privateKey, cipher);

				
				return ciphertext;
			} catch (Exception e2) {
				logger.debug("Error RSA para el descifrado según: " + usedAlgorithm, e2);
				try {
					usedAlgorithm = RSA_ECB_PKCS1;
					Cipher cipher = Cipher.getInstance(usedAlgorithm, provider);
					if (logger.isDebugEnabled()) {
						logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + cipher.getProvider().getName());
					}
					// Se recupera el texto en claro
					byte[] ciphertext = decryptText(cryptedText, provider, privateKey, cipher);

					return ciphertext;
				} catch (Exception e3) {
	                logger.debug("Error RSA para el descifrado según: " + usedAlgorithm + " con el proveedor " + provider, e3);
	                try {
	                    usedAlgorithm = "RSA";
	                    Cipher cipher = Cipher.getInstance(usedAlgorithm, provider);
	                    if (logger.isDebugEnabled()) {
	                        logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + cipher.getProvider().getName());
	                    }
	                    // Se recupera el texto en claro
	                    byte[] ciphertext = decryptText(cryptedText, provider, privateKey, cipher);

	                    return ciphertext;
	                } catch (Exception e4) {
	                    logger.debug("Error RSA para el descifrado según: " + usedAlgorithm + " con el proveedor " + provider, e4);
    	                try {
    	                    usedAlgorithm = RSA_ECB_PKCS1;
    	                    Cipher cipher = Cipher.getInstance(usedAlgorithm);
    	                    if (logger.isDebugEnabled()) {
    	                        logger.debug("Empleando el algoritmo " + usedAlgorithm + " con el proveedor " + cipher.getProvider().getName());
    	                    }
    	                    // Se recupera el texto en claro
    	                    byte[] ciphertext = decryptText(cryptedText, provider, privateKey, cipher);
    
    	                    return ciphertext;
    	                } catch (Exception e5) {
    	                    logger.debug("No se pudo desencriptar", e5);
    	                }
	                }
				}

				throw new SecurityException("Error RSA - No se pudo desencriptar", e2);
			} finally {
				if (provider != null && Security.getProvider(provider.getName()) != null) {
	        		Security.removeProvider(provider.getName());
	        	}
			}
		}
	}

    private byte[] decryptText(final char[] cryptedText, Provider provider,
            PrivateKey privateKey, Cipher cipher) throws InvalidKeyException,
            NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException {
        //Workaround Mozilla
        byte[] ciphertext;
        if (provider!= null && provider.getName() != null && provider.getName().contains("Mozilla-JSS")) {
        	if (logger.isDebugEnabled()) {
        		logger.debug("Recuperando clave a través de Mozilla-JSS");
        	}
        	cipher.init(Cipher.UNWRAP_MODE, privateKey);
        	ciphertext = cipher.unwrap(Base64Coder.decode(cryptedText), ConstantsCrypto.TripleDES_ALGORITHM, Cipher.SECRET_KEY).getEncoded();				
        } else {
        	cipher.init(Cipher.DECRYPT_MODE, privateKey);
        	ciphertext = cipher.doFinal(Base64Coder.decode(cryptedText));
        }
        return ciphertext;
    }
		
	/**
	 * <p>Genera y protege mediante tripleDES un nuevo par de claves asimetricas.</p>
	 * @param password Contraseña con la cual se protege simétricamente el par de claves asimétrico
	 * @return
	 */
	public String genNewRSAKeys(String password) {
		try {
			// Se genera el nuevo par de claves RSA
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ConstantsCrypto.RSA_ALGORITHM, ConstantsAPI.PROVIDER_BC_NAME);
			generator.initialize(keySize, random);
			KeyPair newKeys = generator.generateKeyPair();
			
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
		if (usedAlgorithm == RSA_OAEP_KEY) {
			return "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
		} else {
			return "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
		}
	}
	
	/**
	 * Main de pruebas
	 */
	public static void main(String[] args) {
		RSAManager p = new RSAManager();
		// Se crea un nuevo par de claves
		System.out.println("Se solicita el cálculo de un nuevo par de claves asimétricas de " + keySize + " bits");
		Long start = System.currentTimeMillis();
		String protectedPair = p.genNewRSAKeys("ecoestadisticassrepals");
		KeyPair pair = p.unprotectKeyPair(protectedPair, "ecoestadisticassrepals");
		Long time = System.currentTimeMillis() - start;
		System.out.println("Claves obtenidas. " + "Tiempo consumido (ms): " + time + ". Comienzan las pruebas de encriptación...");
		// Se comienza con la batería de pruebas
		System.out.println("Texto en claro: " + args[0]);
		String buffer = args[0];
		char[] bufferChar = p.protectRSA(buffer, pair.getPrivate()); //p.prvKey);
		buffer = new String(bufferChar);
		System.out.println("Texto encriptado RSA con privada: " + buffer);
		buffer = new String(p.recoverRSA(bufferChar, pair.getPublic()));//p.pubKey));
		System.out.println("Texto desencriptado RSA con pública: " + buffer);
		// Batería de pruebas con ofuscación
		start = System.currentTimeMillis();
		buffer = Utils.obfuscate(new String(p.protectRSA(buffer, pair.getPublic())));
		System.out.println("Encriptado RSA con pública y ofuscado: " + buffer);
		buffer = new String(p.recoverRSA(Utils.undoObfuscate(buffer.getBytes()).toCharArray(), pair.getPrivate()));
		time = System.currentTimeMillis() - start;
		System.out.println("Texto recuperado con privada: " + buffer + "\nTiempo consumido (ms): " + time);
	}
}
