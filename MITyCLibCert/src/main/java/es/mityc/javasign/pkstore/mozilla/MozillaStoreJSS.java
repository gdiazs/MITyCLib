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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.InitializationValues;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.JSSProvider;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PK11Module;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.util.IncorrectPasswordException;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable.MESSAGES_MODE;
import es.mityc.javasign.pkstore.mozilla.MozillaStoreUtils.LIB_MODE;

/**
 * <p>Facade de acceso a los servicios del almacén de certificados de Mozilla mediante el uso de JSS.</p>
 * 
 */
public class MozillaStoreJSS implements IPKStoreManager {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MozillaStoreJSS.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

    /** Nombre del módulo que gestiona el almacén interno de Mozilla. */
    private static final String STR_FIX_JSS_BUILT_IN = "Builtin Object Token";
    /** Modo de funcionamiento de login de los tokens. */
	private MozillaTokenLoginModeEnum loginMode = MozillaTokenLoginModeEnum.getDefault();
	/** Tiempo en minutos de espera antes de tener que volver a logar en caso de que los tokens se desactiven por tiempo. */
	private int loginTimeoutMinutes = 5;

	/** Mananger general de las funciones criptográficas de Mozilla con JSS. */
	private static CryptoManager cm = null;
	
	/**
	 * Constructor. En la inicialización Hay que indicar el nombre del almacén
	 * @param profile Ruta donde se encuentra el perfil de usuario de Mozilla
	 */
	public MozillaStoreJSS(String profile) throws CertStoreException {
		this(profile, LIB_MODE.ONLY_JSS);
	}
	
	/**
	 * Constructor. En la inicialización Hay que indicar el nombre del almacén
	 * @param profile Ruta donde se encuentra el perfil de usuario de Mozilla
	 * @param mode Indica el modo en el que se copiarán las librerías nativas
	 */
	public MozillaStoreJSS(String profile, LIB_MODE mode) throws CertStoreException {
		if (cm == null)
			initialize(profile, mode);
	}

	/**
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getCertPath(java.security.cert.X509Certificate)
	 */
	public CertPath getCertPath(X509Certificate certificate) throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getPrivateKey(java.security.cert.X509Certificate)
	 */
	public PrivateKey getPrivateKey(X509Certificate certificate) throws CertStoreException {
		byte[] certIssuerName = null;
		INTEGER serialNumber = null;
		try {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Cargando JSS con el manager ");
				LOG.debug(cm!=null?cm.getClass():"Nulo");
			}
			certIssuerName = certificate.getIssuerX500Principal().getEncoded();
			serialNumber = new INTEGER(certificate.getSerialNumber());
			if (LOG.isDebugEnabled()) {
				LOG.debug("Buscando en el almacén el certificado expedido por "+ new String(certIssuerName) + " y serial " + serialNumber);
			}
			org.mozilla.jss.crypto.X509Certificate certJSS = cm.findCertByIssuerAndSerialNumber(certIssuerName, serialNumber);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Certificado encontrado en el almacén: " + certJSS.getSubjectDN());
			}
			
			PrivateKey pk = cm.findPrivKeyByCert(certJSS);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Clave privada asociada encontrada:" + pk!=null?pk.toString():"No encontrada");
			}
			
			
			// Workaround para mozilla firefox
			String certIssuer = certificate.getIssuerDN().getName().replaceAll(" ", "");
			Enumeration< ? > enModules = cm.getModules();
			boolean modulesHasMore = enModules.hasMoreElements();
			while (modulesHasMore) {
				PK11Module module = (PK11Module) enModules.nextElement();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Modulo: " + module.getName());
				}
				modulesHasMore = enModules.hasMoreElements();
				Enumeration< ? > enTok = module.getTokens();
				boolean tokHasMore = enTok.hasMoreElements();
				while (tokHasMore) {
					PK11Token token = (PK11Token) enTok.nextElement();
					if (LOG.isTraceEnabled()) {
						LOG.trace("Token: " + token.getName());
					}
					tokHasMore = enTok.hasMoreElements();

					try {
						CryptoStore store = token.getCryptoStore();
						org.mozilla.jss.crypto.X509Certificate[] certs = store.getCertificates();
						for(org.mozilla.jss.crypto.X509Certificate current:certs) {
							String currentIssuer = current.getIssuerDN().getName().replaceAll(" ", "");
							if (currentIssuer.equals(certIssuer) &&
									(current.getSerialNumber()).equals(certificate.getSerialNumber())) {
								if (LOG.isTraceEnabled()) {
									LOG.trace("Se ha encontrado coincidencia en el token " + token.getName());
								}
								cm.setThreadToken(cm.getTokenByName(token.getName()));
								break;
							}
						}						
						break;			
					} catch(Exception e) {
						if (LOG.isTraceEnabled()) {
							LOG.error(e);
						}
						continue;
					}
				}
			}			
			
			return pk;
		} catch (Exception ex) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Error al acceder al token criptográfico. Reintentando logarse", ex);
			}

			try {
				// Recoge los tokens externos y les da a cada uno un passwordcallback que indica el nombre del dispositivo
				if (LOG.isTraceEnabled()) {
					LOG.trace("Procesando modulos");
				}
				Enumeration< ? > enModules = cm.getModules();
				boolean modulesHasMore = enModules.hasMoreElements();
				while (modulesHasMore) {
					if (LOG.isTraceEnabled()) {
						LOG.trace("Procesando modulo PK11 de mozilla");
					}
					PK11Module module = (PK11Module) enModules.nextElement();
					modulesHasMore = enModules.hasMoreElements();
					module.reloadTokens();
					Enumeration< ? > enTok = module.getTokens();
					boolean tokHasMore = enTok.hasMoreElements();
					while (tokHasMore) {
						if (LOG.isTraceEnabled()) {
							LOG.trace("Procesando token");
						}
						PK11Token token = (PK11Token) enTok.nextElement();
						if (LOG.isTraceEnabled()) {
							LOG.trace("Token: " + token.getName());
						}
						tokHasMore = enTok.hasMoreElements();

						// Fix para el error de las librerías JSS de Linux
						if (STR_FIX_JSS_BUILT_IN.equals(token.getName())) {
							continue;
						}

						if ((!token.isInternalCryptoToken()) && (!token.isInternalKeyStorageToken())) {
							if (LOG.isTraceEnabled()) {
								LOG.trace("Procesando token externo");
							}
							if (token.isPresent()) {
								if (token.isLoggedIn()) {
									token.logout();
								}
								if (LOG.isTraceEnabled()) {
									LOG.trace("Loggin de token...");
								}
								int tries = 0;
								while (tries < 3) {
									try {
										token.setLoginMode(loginMode.getInteger());
										if (this.loginMode == MozillaTokenLoginModeEnum.TIMEOUT) {
											token.setLoginTimeoutMinutes(loginTimeoutMinutes);
										}
										token.login(MozillaStoreUtils.getPassHandler(MESSAGES_MODE.AUTO_TOKEN, null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_8)));
										tries += 3;
										if (LOG.isTraceEnabled()) {
											LOG.trace("Loggin de token correcto!");
										}
									} catch (IncorrectPasswordException ex2) {
										LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_6));
										tries++;
									} catch (TokenException ex2) {
										LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_7, token.getName()), ex2);
										tries++;
									}
								}
							}
							if (token.isLoggedIn()) {
								if (LOG.isTraceEnabled()) {
									LOG.trace("Accediendo a token...");
								}
								CryptoStore store = token.getCryptoStore();
								
								org.mozilla.jss.crypto.X509Certificate[] certs = store.getCertificates();
								org.mozilla.jss.crypto.X509Certificate certCandidato = null;
								boolean isFound = false;
								for(int i = 0; i < certs.length; ++i) {
									certCandidato = certs[i];
									if (LOG.isTraceEnabled()) {
										LOG.trace("Certificado candidato: " + certCandidato.getNickname());
									}
									try {
										if (new String(certCandidato.getEncoded()).equals(new String(certificate.getEncoded()))) {
											if (LOG.isDebugEnabled()) {
												LOG.debug("Correspondencia encontrada");
											}
											isFound = true;
											break;
										}
									} catch (CertificateEncodingException e) {
										LOG.error("No se pudo recuperar el certificado:" + certCandidato.getNickname());
										continue;
									}
								}

								if (!isFound) {
									if (LOG.isDebugEnabled()) {
										LOG.debug("No se han encontrado correspondencias en este token. Se continua");
									}
									continue;
								}
								
								org.mozilla.jss.crypto.X509Certificate certJSS = cm.findCertByIssuerAndSerialNumber(certIssuerName, serialNumber);
								if (LOG.isDebugEnabled()) {
									LOG.debug("Certificado encontrado en el almacén: " + certJSS.getSubjectDN());
								}
								PrivateKey pk = cm.findPrivKeyByCert(certJSS);
								if (LOG.isDebugEnabled()) {
									LOG.debug("Clave privada asociada encontrada:" + pk!=null?pk.toString():"No encontrada");
								}
								return pk;
							}
						}
					}
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("Modulos procesados sin encontrar correspondencia");
				}           
				throw new CertStoreException("No se encuentra la clave privada", ex);
			} catch (SecurityException ex1) {
				// No se puede acceder al almacén de certificados de mozilla
				LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex1);
				throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex1);  
			} catch (TokenException ex1) {
				LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex1);
				throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex1);
			} catch (ObjectNotFoundException ex1) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Error al buscar la clave privada", ex);
				}
				throw new CertStoreException(ex);
			}
		}
	}

	/**
     * @param cert Certificado para el que se necesita acceso al provider
     * @return Provider asociado a este almacén
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getProvider(X509Certificate)
	 */
	public Provider getProvider(final X509Certificate cert) {
		return new JSSProvider();
	}

	/**
	 * Obtiene los certificados que tienen clave privada
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getSignCertificates()
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		return getCertificates(true);
	}
	
	/**
	 * Obtiene los certificados que no tienen clave privada asociada
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getSignCertificates()
	 */
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
		
		if (cm == null) {
			LOG.error("No se ha cargado el módulo CSP para Mozilla");
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9));
		}

		ArrayList<X509Certificate> allCertsPublic = new ArrayList<X509Certificate>();
		ArrayList<X509Certificate> allCertsPrivate = new ArrayList<X509Certificate>();
		try {
			// Recoge los tokens externos y les da a cada uno un passwordcallback que indica el nombre del dispositivo
			if (LOG.isTraceEnabled()) {
				LOG.trace("Procesando modulos");
			}
			Enumeration< ? > enModules = cm.getModules();
			boolean modulesHasMore = enModules.hasMoreElements();
			while (modulesHasMore) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Procesando modulo PK11 de mozilla");
				}
				PK11Module module = (PK11Module) enModules.nextElement();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Modulo: " + module.getName());
				}
				modulesHasMore = enModules.hasMoreElements();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Recargando tokens");
				}
				module.reloadTokens();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Tokens recargados");
				}
				Enumeration< ? > enTok = module.getTokens();
				if (LOG.isTraceEnabled()) {
					LOG.trace("Tokens del módulo obtenidos: " + enTok.hasMoreElements());
				}
				boolean tokHasMore = enTok.hasMoreElements();
				while (tokHasMore) {
					if (LOG.isTraceEnabled()) {
						LOG.trace("Procesando token");
					}
					PK11Token token = (PK11Token) enTok.nextElement();
					if (LOG.isTraceEnabled()) {
						LOG.trace("Token: " + token.getName());
					}
					tokHasMore = enTok.hasMoreElements();

					// Fix para el error de las librerías JSS de Linux
					if (STR_FIX_JSS_BUILT_IN.equals(token.getName())) {
						continue;
					}

					if ((!token.isInternalCryptoToken()) && (!token.isInternalKeyStorageToken())) {
						if (LOG.isTraceEnabled()) {
							LOG.trace("Procesando token externo");
						}
						if (token.isPresent()) {
							if (token.isLoggedIn()) {
								// Comprobar si la configuracion ha cambiado
								boolean doLogout = (loginMode != MozillaTokenLoginModeEnum.getLoginMode(token.getLoginMode()));
								if (!doLogout && loginMode == MozillaTokenLoginModeEnum.TIMEOUT) {
									doLogout = loginTimeoutMinutes != token.getLoginTimeoutMinutes();
								}

								// Si ha cambiado hacer un logout
								if (doLogout) {
									token.logout();
								}
							}
							if (!token.isLoggedIn()) {
								if (LOG.isTraceEnabled()) {
									LOG.trace("Loggin de token...");
								}
								int tries = 0;
								while (tries < 3) {
									try {
										token.setLoginMode(loginMode.getInteger());
										if (this.loginMode == MozillaTokenLoginModeEnum.TIMEOUT) {
											token.setLoginTimeoutMinutes(loginTimeoutMinutes);
										}
										token.login(MozillaStoreUtils.getPassHandler(MESSAGES_MODE.AUTO_TOKEN, null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_8)));
										tries += 3;
										if (LOG.isTraceEnabled()) {
											LOG.trace("Loggin de token correcto!");
										}
										cm.setThreadToken(token);
									} catch (IncorrectPasswordException ex) {
										LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_6));
										tries++;
									} catch (TokenException ex) {
										LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_7, token.getName()), ex);
										tries++;
									}
								}
							}
							if (token.isLoggedIn()) {
								if (LOG.isTraceEnabled()) {
									LOG.trace("Accediendo a token...");
								}
								CryptoStore store = token.getCryptoStore();
								org.mozilla.jss.crypto.X509Certificate[] certs = store.getCertificates();
								for (int i = 0; i < certs.length; i++) {
									X509Certificate cert = MozillaStoreUtils.convert(certs[i]);
									boolean[] usage = cert.getKeyUsage();
									// permite los certificados que tienen indicado como uso la firma digital o que no tienen indicado ningún permiso
									if ((cert != null) && ((usage == null) || (usage[0]) || (usage[1]))) {
										allCertsPrivate.add(cert);
									}
									else
										allCertsPublic.add(cert);
								}
							}
						}
					}
				}
				if (LOG.isTraceEnabled()) {
					LOG.trace("Modulo P11 procesado");
				}
			}            

			// Recoge todos los certificados que tienen una clave privada en el storage interno del mozilla
			if (LOG.isTraceEnabled()) {
				LOG.trace("Pide certificados");
			}
			org.mozilla.jss.crypto.X509Certificate[] certs = cm.getInternalKeyStorageToken().getCryptoStore().getCertificates();
			if (LOG.isTraceEnabled()) {
				if (certs != null) {
					LOG.trace("Se han obtenido " + certs.length + " certificados");
				} else {
					LOG.trace("No hay certificados disponibles");
				}
			}

			for (int i = 0; i < certs.length; i++) {
				try {
					if (LOG.isTraceEnabled()) {
						LOG.trace("Buscando clave privada para: " + certs[i]);
					}
					if (cm.findPrivKeyByCert(certs[i]) != null) {
						X509Certificate cert = MozillaStoreUtils.convert(certs[i]);
						allCertsPrivate.add(cert);
					} else {
						allCertsPublic.add(MozillaStoreUtils.convert(certs[i]));
					}
				} catch (ObjectNotFoundException ex) {
					if (LOG.isTraceEnabled()) {
						LOG.trace("No hay clave privada");
					}
				}
			}
		} catch (SecurityException ex) {
			// No se puede acceder al almacén de certificados de mozilla
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex);
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex);  
		} catch (TokenException ex) {
			// No se puede acceder al almacén de certificados de mozilla
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex);
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_9), ex);  
		}

		if (getPrivates) {
			return allCertsPrivate;
		} else {
			return allCertsPublic;
		}
	}
	
	/**
	 * Obtiene los certificados que son de confianza. Operación no soportada actualmente para este almacén.
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

		MozillaStoreUtils.initialize(profile, mode);

		try {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Se levanta el proveedor JSS");
			}
			InitializationValues iv = new InitializationValues(profile);
			iv.installJSSProvider = false;
			CryptoManager.initialize(iv);
			cm = CryptoManager.getInstance();
		} catch (UnsatisfiedLinkError e) {
			LOG.debug("No se pudo cargar la instancia de la librería JSS: " + e.getMessage(), e);
			throw new CertStoreException(e);
		} catch (KeyDatabaseException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_2, ex.getMessage()), ex);
		} catch (CertDatabaseException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_2, ex.getMessage()), ex);
		} catch (AlreadyInitializedException ex) {
		} catch (GeneralSecurityException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_2, ex.getMessage()), ex);
		} catch (NotInitializedException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MOZILLA_2, ex.getMessage()), ex);
		}
		if (cm != null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Capturando slot para peticiones de PIN");
			}
			cm.setPasswordCallback(MozillaStoreUtils.getPassHandler(MESSAGES_MODE.AUTO, null, null));
		}
	}
	
	/**
	 * Returns the login mode: ONE_TIME, TIMEOUT, or EVERY_TIME. The default is ONE_TIME.
	 * @return modo de login
	 */
	public MozillaTokenLoginModeEnum getLoginMode() {
		return loginMode;
	}

	/**
	 * Sets the login mode of this token.
	 * @param mode ONE_TIME, TIMEOUT, or EVERY_TIME
	 */
	public void setLoginMode(MozillaTokenLoginModeEnum mode) {
		this.loginMode = mode;
	}

	/**
	 * Returns the login timeout period. The timeout is only used if the login mode is TIMEOUT.
	 * @return timeout de login en minutos 
	 */
	public int getLoginTimeoutMinutes() {
		return loginTimeoutMinutes;
	}

	/**
	 * Sets the timeout period for logging in. This will only be used if the login mode is TIMEOUT.
	 * @param timeoutMinutes
	 */
	public void setLoginTimeoutMinutes(int timeoutMinutes) {
		this.loginTimeoutMinutes = timeoutMinutes;
	}
}
