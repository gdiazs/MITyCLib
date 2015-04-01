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
package es.mityc.javasign.pass;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.ResourceBundle;

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

import es.mityc.javasign.utils.HexUtils;

/**
 * <p>Gestiona la seguridad de las contraseñas mediante un sistema PBE.</p>
 * <p>Los parámetros de configuración utilizados por este manager son:
 * 	<ul>
 * 		<li>simplePBE.salt: cadena en hexadecimal de 8 bytes que indica el salt del PBE.</li>
 * 		<li>simplePBE.iteration: número decimal que indica el número de iteración del PBE.</li>
 * 		<li>simplePBE.masterkey: cadena de texto con la contraseña maestra base del PBE.</li>
 * 	</ul>
 * </p>
 */
public class PBESecurity implements IPassSecurity {
	
	/** LOGGER. */
	private static final Log LOGGER = LogFactory.getLog(PBESecurity.class);
	
	/** Nombre del fichero de configuración de seguridad. */
	private static final String CONFIG_SEC_CLIENT = "config/security";
	/** Propiedad con la Salt. */
	private static final String PROP_SEC_SALT = "simplePBE.salt";
	/** Propiedad con la Iteration. */
	private static final String PROP_SEC_ITERATION = "simplePBE.iteration";
	/** Propiedad con la Master Key. */
	private static final String PROP_SEC_MASTERKEY = "simplePBE.masterkey";
	
	/** Salt de las contraseñas PBE. */
	private byte[] salt = null;
	/** Iteration de las contraseñas PBE. */
	private int iter = 0;
	/** Secreto maestro de la PBE. */
	private transient String masterPass = null;

	/**
	 * <p>Constructor.</p>
	 * @throws PassSecurityException Lanzada si no se puede inicializar el objeto
	 */
	public PBESecurity() throws PassSecurityException {
		init();
	}
	
	/**
	 * <p>Constructor.</p>
	 * @param saltBase Salt
	 * @param iteration Número de iteración
	 * @param password Contraseña maestra
	 * @throws PassSecurityException Lanzada si no se puede inicializar
	 */
	public PBESecurity(byte[] saltBase, final int iteration, final String password) throws PassSecurityException {
		this.salt = saltBase;
		this.iter = iteration;
		this.masterPass = new String(password);
	}
	
	/**
	 * <p>Constructor.</p>
	 * @param props Propiedades de configuración del gestionador de contraseñas.
	 * @throws PassSecurityException Lanzada si no se puede inicializar el objeto
	 */
	public PBESecurity(Properties props) throws PassSecurityException {
		init(props);
	}
	
	/**
	 * <p>Inicializa la configuración de seguridad.</p>
	 * @throws PassSecurityException lanzada cuando falta algún parámetro de configuración
	 */
	protected void init() throws PassSecurityException {
		try {
			ResourceBundle rb = ResourceBundle.getBundle(CONFIG_SEC_CLIENT);
			init(rb);
		} catch (MissingResourceException ex) {
			LOGGER.warn("Fichero de configuración de seguridad tiene datos erróneos");
			LOGGER.trace(ex.getMessage(), ex);
			throw new PassSecurityException("Recurso de configuración no disponible: " + ex.getKey()); 
		} catch (NumberFormatException ex) {
			LOGGER.warn("Fichero de configuración de seguridad tiene datos erróneos");
			LOGGER.trace(ex.getMessage(), ex);
			throw new PassSecurityException("Formato numérico inadecuado: " + ex.getMessage()); 
		}
	}
	
	/**
	 * <p>Inicializa la configuración de seguridad.</p>
	 * @param rb Configuración
	 * @throws PassSecurityException lanzada cuando falta algún parámetro de configuración
	 */
	protected void init(final ResourceBundle rb) throws PassSecurityException {
		try {
			init(rb.getString(PROP_SEC_SALT), rb.getString(PROP_SEC_ITERATION), rb.getString(PROP_SEC_MASTERKEY));
		} catch (MissingResourceException ex) {
			LOGGER.warn("Fichero de configuración de seguridad tiene datos erróneos");
			LOGGER.trace(ex.getMessage(), ex);
			throw new PassSecurityException("Recurso de configuración no disponible: " + ex.getKey()); 
		}
	}
	
	/**
	 * <p>Inicializa la configuración de seguridad.</p>
	 * @param props Configuración
	 * @throws PassSecurityException lanzada cuando falta algún parámetro de configuración
	 */
	protected void init(final Properties props) throws PassSecurityException {
		try {
			init(props.getProperty(PROP_SEC_SALT), props.getProperty(PROP_SEC_ITERATION), props.getProperty(PROP_SEC_MASTERKEY));
		} catch (NullPointerException ex) {
			LOGGER.warn("Fichero de configuración de seguridad tiene datos erróneos");
			LOGGER.trace(ex.getMessage(), ex);
			throw new PassSecurityException("Recurso de configuración no disponible"); 
		}
	}

	/**
	 * <p>Inicializa la configuración de seguridad.</p>
	 * @param saltStr Cadena de texto con el valor hexadecimal de la sal
	 * @param iterStr Cadena de texto con el valor decimal de las iteraciones
	 * @param passStr Cadena de texto con la contraseña maestra
	 * @throws PassSecurityException lanzada cuando falta algún parámetro de configuración
	 */
	protected void init(final String saltStr, final String iterStr, final String passStr) throws PassSecurityException {
		LOGGER.trace("Inicializando objeto de seguridad");
		try {
			salt = HexUtils.convert(saltStr);
			iter = Integer.parseInt(iterStr);
			masterPass = new String(passStr);
		} catch (NumberFormatException ex) {
			LOGGER.warn("Fichero de configuración de seguridad tiene datos erróneos");
			LOGGER.trace(ex.getMessage(), ex);
			throw new PassSecurityException("Formato numérico inadecuado: " + ex.getMessage()); 
		}
	}
	
	/**
	 * <p>Protege una contraseña.</p>
	 * @param pass contraseña a proteger
	 * @return contraseña protegida
	 * @throws PassSecurityException Lanzada cuando se produce algún error al proteger la contraseña
	 */
	public String protect(final String pass) throws PassSecurityException {
		try {
			// Create PBE parameter set
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iter);
	
			PBEKeySpec pbeKeySpec = new PBEKeySpec(masterPass.toCharArray());
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
	
		    // Create PBE Cipher
		    Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
	
		    // Initialize PBE Cipher with key and parameters
		    pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
	
		    // Our cleartext
		    byte[] cleartext = pass.getBytes();
	
		    // Encrypt the cleartext
		    byte[] ciphertext = pbeCipher.doFinal(cleartext);
		    
		    return hexData(ciphertext);
		} catch (NoSuchAlgorithmException ex) {
			throw new PassSecurityException(ex);
		} catch (InvalidKeySpecException ex) {
			throw new PassSecurityException(ex);
		} catch (NoSuchPaddingException ex) {
			throw new PassSecurityException(ex);
		} catch (InvalidKeyException ex) {
			throw new PassSecurityException(ex);
		} catch (InvalidAlgorithmParameterException ex) {
			throw new PassSecurityException(ex);
		} catch (IllegalBlockSizeException ex) {
			throw new PassSecurityException(ex);
		} catch (BadPaddingException ex) {
			throw new PassSecurityException(ex);
		}
	}
	
	/**
	 * <p>Convierte un conjunto de datos binarios en su equivalente de texto hexadecimal.</p>
	 * @param data datos binarios
	 * @return cadena de texto hexadecimal
	 */
	public String hexData(final byte[] data) {
		StringBuffer sb = new StringBuffer("{");
		sb.append(HexUtils.convert(data)).append("}");
		return sb.toString();
	}
	
	/**
	 * <p>Desprotege una contraseña convirtiéndola en texto plano.</p>
	 * @param pass contraseña protegida/desprotegida
	 * @return contraseña desprotegida
	 * @throws PassSecurityException Lanzada cuando no se puede recuperar la contraseña
	 */
	public String recover(final String pass) throws PassSecurityException {
		if (pass.startsWith("{")) {
			String dataStr = pass.substring(1, pass.indexOf("}"));
			byte[] data = HexUtils.convert(dataStr);
			try {
				// Create PBE parameter set
				PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iter);
		
				PBEKeySpec pbeKeySpec = new PBEKeySpec(masterPass.toCharArray());
				SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
			    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
		
			    // Create PBE Cipher
			    Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
		
			    // Initialize PBE Cipher with key and parameters
			    pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		
			    // Encrypt the cleartext
			    byte[] ciphertext = pbeCipher.doFinal(data);
			    
			    return new String(ciphertext);
			} catch (NoSuchAlgorithmException ex) {
				throw new PassSecurityException(ex);
			} catch (InvalidKeySpecException ex) {
				throw new PassSecurityException(ex);
			} catch (NoSuchPaddingException ex) {
				throw new PassSecurityException(ex);
			} catch (InvalidKeyException ex) {
				throw new PassSecurityException(ex);
			} catch (InvalidAlgorithmParameterException ex) {
				throw new PassSecurityException(ex);
			} catch (IllegalBlockSizeException ex) {
				throw new PassSecurityException(ex);
			} catch (BadPaddingException ex) {
				throw new PassSecurityException(ex);
			}
		} else {
			return pass;
		}
	}
	

}
