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
package es.mityc.javasign.pkstore.mozilla;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.PkProxyProvider;
import iaik.pkcs.pkcs11.PkcsProvider;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

import java.io.File;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable.MESSAGES_MODE;
import es.mityc.javasign.pkstore.mozilla.MozillaStoreUtils.LIB_MODE;
import es.mityc.javasign.utils.OSTool;

/**
 * <p>Facade de acceso a los servicios del almacén de certificados de Mozilla mediante el uso de JSS.</p>
 * 
 */
public class MozillaStorePKCS11 implements IPKStoreManager {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MozillaStorePKCS11.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Mananger general de las funciones criptográficas de Mozilla con NSS-PKCS11Wrapper. */
	private static Module cmNss = null;
	
	/**
	 * Constructor. En la inicialización Hay que indicar el nombre del almacén
	 * @param profile Ruta donde se encuentra el perfil de usuario de Mozilla
	 */
	public MozillaStorePKCS11(String profile) throws CertStoreException {
		this(profile, LIB_MODE.ONLY_PKCS11);
	}
	
	/**
	 * Constructor. En la inicialización Hay que indicar el nombre del almacén
	 * @param profile Ruta donde se encuentra el perfil de usuario de Mozilla
	 * @param mode Indica el modo en el que se copiarán las librerías nativas
	 */
	public MozillaStorePKCS11(String profile, LIB_MODE mode) throws CertStoreException {
		if (cmNss == null)
			initialize(profile, mode);
	}

	/**
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getCertPath(java.security.cert.X509Certificate)
	 */
	public CertPath getCertPath(X509Certificate certificate) throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * Obtiene la clave privada de un certificado
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getPrivateKey(java.security.cert.X509Certificate)
	 */
	public PrivateKey getPrivateKey(X509Certificate certificate) throws CertStoreException {
		if (cmNss != null) {
			try {
				Slot[] availSlots = cmNss.getSlotList(Module.SlotRequirement.ALL_SLOTS);
				if (availSlots.length == 0) {
					LOG.error("No se puede acceder a Firefox, no se han encontrado slots libres.");
					return null;
				}
				for (int i = 0; i < availSlots.length; ++i) {
					if (LOG.isDebugEnabled()) {
						LOG.debug("Procesando slot " + i);
					}

					Token tok = availSlots[i].getToken();
					Session sess = tok.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
					if (LOG.isDebugEnabled()) {
						LOG.debug("Session: " + sess.getSessionInfo());
					}
					
					if (tok.getTokenInfo().isLoginRequired()) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Solicitando contraseña de acceso");
						}
						PasswordCallback passDialog = MozillaStoreUtils.getPassHandler(MESSAGES_MODE.AUTO_TOKEN, null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_8));
						Password pass = passDialog.getPasswordFirstAttempt(new PasswordCallbackInfo("Firefox", 1));
						if (LOG.isDebugEnabled()) {
							LOG.debug("PIN obtenido, Autenticando");
						}
						try {
							sess.login(Session.UserType.USER, pass.getCharCopy());
						} catch(Exception e) {
							throw new CertStoreException("Contraseña incorrecta", e);
						}
					}
					
					if (LOG.isDebugEnabled()) {
						LOG.debug("Resolviendo alias del certificado");
					}
					X509PublicKeyCertificate tempCert = new X509PublicKeyCertificate();
					sess.findObjectsInit(tempCert);
					iaik.pkcs.pkcs11.objects.Object[] foundCerts = sess.findObjects(100); 
					LOG.debug("Se han encontrado " + foundCerts.length + " certificados en el almacén de Firefox");
					sess.findObjectsFinal();
					String labelToFind = null;
					for (int j = 0; j < foundCerts.length; j++) {
						if (Arrays.equals(certificate.getIssuerX500Principal().getEncoded(), 
								((X509PublicKeyCertificate)foundCerts[j]).getIssuer().getByteArrayValue())) {
							// Codificado en ASN1 DER según el estándar PKCS11 --> http://answerpot.com/showthread.php?2542018-Problem+with+serial+number+on+Pkcs11+token
							byte[] serialPkcs11 = ((X509PublicKeyCertificate)foundCerts[j]).getSerialNumber().getByteArrayValue();			
							serialPkcs11 = Arrays.copyOfRange(serialPkcs11, 2, serialPkcs11.length);
							if (Arrays.equals(certificate.getSerialNumber().toByteArray(), serialPkcs11)) {
								labelToFind = ((X509PublicKeyCertificate)foundCerts[j]).getLabel().toString();
								break;
							}
						}
					}
					
					if (LOG.isDebugEnabled()) {
						LOG.debug("Buscando clave privada asociada al alias " + labelToFind);
					}
					RSAPrivateKey tempKey = new RSAPrivateKey();
					tempKey.getSign().setBooleanValue(Boolean.TRUE);
					sess.findObjectsInit(tempKey);
					iaik.pkcs.pkcs11.objects.Object[] foundKeys = sess.findObjects(100); 
					sess.findObjectsFinal();
					LOG.debug("Encontradas " + foundKeys.length + " claves privadas");					
					
					if (foundKeys != null && foundKeys.length > 0) {						
						for (int j = 0; j < foundKeys.length; j++) {
							RSAPrivateKey tokenkey = (RSAPrivateKey) foundKeys[j];
							if (labelToFind.equals(new String(tokenkey.getLabel().getCharArrayValue()))) {
								if (LOG.isDebugEnabled()) {
									LOG.debug("Devolviendo pasarela a la clave privada");
								}
								return new PkProxyProvider(certificate, (RSAPrivateKey) foundKeys[j], sess);
							}
						}
						if (LOG.isDebugEnabled()) {
							LOG.debug("Clave privada no encontrada");
						}
						return null;
					}
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("Clave privada no encontrada");
				}
				return null;
			} catch(Exception e) {
				throw new CertStoreException("No se pudo acceder al repositorio de certificados de Firefox", e);
			}
		} else {
			throw new CertStoreException("No se pudo acceder al repositorio de certificados de Firefox");
		}
	}

	/**
     * @param cert Certificado para el que se necesita acceso al provider
     * @return Provider asociado a este almacén
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getProvider(X509Certificate)
	 */
	public Provider getProvider(final X509Certificate cert) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Devolviendo instancia del proveedor criptográfico PKCS11Wrapper+NSS");
		}
		return new PkcsProvider();
	}

	/**
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getSignCertificates()
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		return getCertificates(true);
	}
	
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		return getCertificates(false);
	}
	
	/**
	 * <p>Extrae certificados del token de Mozilla
	 * @param getPrivates <code>true</code> para obtener sólo los certificados con clave privada.
	 * 					  <code>false</code> para obtener los certificados sin clave priva asociada. 
	 * @return Lista de certificados obtenida
	 * @throws CertStoreException 
	 */
	private List<X509Certificate> getCertificates(boolean getPrivates) throws CertStoreException {
		if (cmNss == null) {
			LOG.error("No se ha cargado el módulo CSP-PKCS11 para Mozilla");
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9));
		}
		ArrayList<X509Certificate> allCertsPublic = new ArrayList<X509Certificate>();
		ArrayList<X509Certificate> allCertsPrivate = new ArrayList<X509Certificate>();
		int foundCertsTotal = 0;
		try {
			Slot[] availSlots = cmNss.getSlotList(Module.SlotRequirement.ALL_SLOTS);
			if (availSlots.length == 0) {
				LOG.error("No se puede acceder a Firefox, no se han encontrado slots libres.");
				return null;
			} else if (LOG.isDebugEnabled()) {
				LOG.debug("Slots disponibles: " + availSlots.length);
			}
			// Se comprueban todos los slot diponibles
			for (int i = 0; i < availSlots.length; ++i) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Procesando slot " + i);
				}

				Token tok = availSlots[i].getToken();
				Session sess = tok.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
				if (LOG.isTraceEnabled()) {
					LOG.trace("Session: " + sess.getSessionInfo());
				}

				if (tok.getTokenInfo().isLoginRequired()) {
					if (LOG.isDebugEnabled()) {
						LOG.debug("Solicitando contraseña de acceso");
					}
					PasswordCallback passDialog = MozillaStoreUtils.getPassHandler(MESSAGES_MODE.AUTO_TOKEN, null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_8));
					Password pass = passDialog.getPasswordFirstAttempt(new PasswordCallbackInfo("Firefox", 1));
					if (LOG.isDebugEnabled()) {
						LOG.debug("PIN obtenido, Autenticando");
					}
					try {
						sess.login(Session.UserType.USER, pass.getCharCopy());
					} catch(Exception e) {
						LOG.error("Contraseña incorrecta", e);
						continue;
					}
				}
				
				// Se buscan todos los certificados
				X509PublicKeyCertificate tempCert = new X509PublicKeyCertificate();
				sess.findObjectsInit(tempCert);
				iaik.pkcs.pkcs11.objects.Object[] foundCerts = sess.findObjects(100); 
				LOG.debug("Se han encontrado " + foundCerts.length + " certificados");
				foundCertsTotal += foundCerts.length;
				sess.findObjectsFinal();

				if (getPrivates) {
					// Se buscan todas las claves privadas
					iaik.pkcs.pkcs11.objects.PrivateKey tempKey = new iaik.pkcs.pkcs11.objects.PrivateKey();
					sess.findObjectsInit(tempKey);
					iaik.pkcs.pkcs11.objects.Object[] privateKeys = sess.findObjects(100); 
					LOG.debug("Encontradas " + privateKeys.length + " claves privadas");
					sess.findObjectsFinal();

					// Se buscan todas las claves públicas
					iaik.pkcs.pkcs11.objects.PublicKey tempKey2 = new iaik.pkcs.pkcs11.objects.PublicKey();
					sess.findObjectsInit(tempKey2);
					iaik.pkcs.pkcs11.objects.Object[] publicKeys = sess.findObjects(100); 
					LOG.debug("Encontradas " + publicKeys.length + " claves publicas");
					sess.findObjectsFinal();

					// Se comprueba la lista de certificados
					for (int j = 0; j < foundCerts.length; j++) {
						X509Certificate cert = MozillaStoreUtils.convert((X509PublicKeyCertificate)foundCerts[j]);
						boolean[] usage = cert.getKeyUsage();
						// Se seleccionan los certificados que tienen indicado como uso la firma digital o que no tienen indicado ningún permiso
						if ((cert != null) && ((usage == null) || (usage[0]) || (usage[1]))) {
							// Se comprueba que el algoritmo de la clave pública es de un tipo válido
							if (!"RSA".equals(cert.getPublicKey().getAlgorithm())) {
								if (LOG.isDebugEnabled()) {
									LOG.debug("Encontrado certificado incompatible: " + cert.getSubjectDN().getName());
									LOG.debug("Algoritmo incompatible de tipo: " + cert.getPublicKey().getAlgorithm());
								}
								continue;
							}
							// Se compara la clave pública del certificado con las disponibles
							PublicKey pubKey = cert.getPublicKey();
							if (!(pubKey instanceof RSAPublicKey)) {
								if (LOG.isDebugEnabled()) {
									LOG.debug("Encontrado certificado incompatible: " + cert.getSubjectDN().getName());
									LOG.debug("Clave pública incompatible de tipo: " + pubKey.getClass());
								}
								continue;
							}
							BigInteger moduloCert = ((RSAPublicKey) pubKey).getModulus();
							BigInteger exponenteCert = ((RSAPublicKey) pubKey).getPublicExponent();
							iaik.pkcs.pkcs11.objects.PublicKey foundPublicKey = null;
							for (int k = 0; k < publicKeys.length; k++) {
								if (publicKeys[k] == null) { // Ya ha sido procesada con éxito
									continue;
								}
								String moduloPKHex = ((iaik.pkcs.pkcs11.objects.RSAPublicKey)publicKeys[k]).getModulus().toString();
								BigInteger moduloPK = new BigInteger(moduloPKHex, 16);
								if (moduloCert.equals(moduloPK)) { // Coincide el módulo
									String exponentePKHex = ((iaik.pkcs.pkcs11.objects.RSAPublicKey)publicKeys[k]).getPublicExponent().toString();
									BigInteger exponentePK = new BigInteger(exponentePKHex, 16);
									if (exponenteCert.equals(exponentePK)) { // Coincide el exponente
										foundPublicKey = (iaik.pkcs.pkcs11.objects.RSAPublicKey)publicKeys[k];
										publicKeys[k] = null; // Se elimina del listado la clave encontrada
										break;
									}
								}
							}

							if (foundPublicKey != null) {
								// Se compara la clave pública encontrada con las privadas disponibles 
								for (int k = 0; k < privateKeys.length; k++) {
									if (privateKeys[k] == null) { // Ya ha sido procesada con éxito
										continue;
									}
									iaik.pkcs.pkcs11.objects.PrivateKey pk = (iaik.pkcs.pkcs11.objects.PrivateKey)privateKeys[k];
									// Se compara el ID de la clave privada y la pública encontrada
									if (pk.getId() != null && pk.getId().equals(foundPublicKey.getId())) {
										// Clave encontrada
										if (LOG.isDebugEnabled()) {
											LOG.debug("Se ha encontrado un certificado asociado a una clave privada presente");
										}
										privateKeys[k] = null; // Se elimina del listado la clave encontrada
										allCertsPrivate.add(cert);
										break;
									}
								}
							}
						}
					}
				} else {
					// Se comprueba la lista de certificados
					for (int j = 0; j < foundCerts.length; j++) {
						X509Certificate cert = MozillaStoreUtils.convert((X509PublicKeyCertificate)foundCerts[j]);
						allCertsPublic.add(cert);
					}
				}
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("Modulo P11 procesado");
			}
		} catch (Exception ex) {
			// No se puede acceder al almacén de certificados de mozilla
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex);
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex);  
		}

		if (getPrivates) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Se devuelven " + allCertsPrivate.size() + " certificados privados de un total de " + foundCertsTotal);
			}
			return allCertsPrivate;
		} else {
			return allCertsPublic;
		}
	}
	
	/**
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getTrustCertificates()
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}
	
	/**
	 *<p> Inicializa el manager general de JSS.</p>
	 * 
	 * @param profile ruta donde se encuentra el perfil de usuario
	 */
	private synchronized void initialize(String profile, LIB_MODE mode) throws CertStoreException {		

		String tmpDir = MozillaStoreUtils.initialize(profile, mode);

		try {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Se levanta el proveedor PKCS11Wrapper+NSS");
			}
			if (tmpDir != null && !tmpDir.endsWith(File.separator)) {
				tmpDir += File.separator;
			}
			
			if (OSTool.getSO().isMacOsX()) {
				MozillaStoreUtils.configureMacNSS(tmpDir);
			}
			
			//cmNss = Module.getInstance(tmpDir + "softokn3.dll");
            cmNss = Module.getInstance("softokn3.dll");
			DefaultInitializeArgs arguments = new DefaultInitializeArgs();
			byte[] stringBytes = null;//("configdir='" + profile + "' certPrefix='' keyPrefix='' secmod=' secmod.db' flags=readOnly").getBytes();
			stringBytes = MozillaStoreUtils.createPKCS11NSSConfigFile(profile, tmpDir).getBytes();
			
			byte[] reservedBytes = new byte[stringBytes.length + 5];
			System.arraycopy(stringBytes, 0, reservedBytes, 0, stringBytes.length);
			arguments.setReserved(reservedBytes);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Módulo instanciado. Incializando con " + new String(stringBytes));
			}
			cmNss.initialize(arguments);
		} catch(Throwable e ) {
			LOG.error("No se pudo cargar la instancia de la librería NSS: " + e.getMessage(), e);
		}
	}
}
