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
package es.mityc.javasign.pkstore.mitycstore;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.Random;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreMaintainer;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.CachedPassHandler;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.DeleteWarnHandler;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.Pkcs11PassHandler;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.PlainPassHandler;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.TranslucentPassHandler;
import es.mityc.javasign.pkstore.mitycstore.PKHandlers.WarnPassHandler;
import es.mityc.javasign.pkstore.mitycstore.mantainer.CertCellRenderer;
import es.mityc.javasign.pkstore.mitycstore.mantainer.DriverTblModel;
import es.mityc.javasign.pkstore.mitycstore.mantainer.KSManagerDialog;
import es.mityc.javasign.pkstore.pkcs11.ConfigMultiPKCS11;
import es.mityc.javasign.pkstore.pkcs11.MultiPKCS11Store;

/**
 * <p>Almacén de certificados propio basado en un almacén de certificados software más acceso a componentes mediante pkcs#11.</p> 
 *  
 */
public class MITyCStore implements IPKStoreManager, IPKStoreMaintainer {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MITyCStore.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	/** Semilla para el generador aleatorio de alias. */
	private static final int RND_MAX_SIZE = 10000;
	/** Alias del almacén. */
	private final String ksAlias = "MITyCKeyStoreAlias";
	
	/** Fichero que contiene la configuración, si existe. */
	private static File confFile = null;
	/** Propiedades recuperadas para el almacén. */
	private Properties prop = null;
	/** Indica si se ha de crear el almacén desde 0 en caso de que no exista. */
	private boolean autocreate = false;
	/** Ruta al almacén de certificados. */
	private static String ksURL = null;
	/** Manejador de contraseñas. Sin cacheo.*/
	private IPassStoreKS passKs = null;
	/** Manejador de contraseñas. Con cacheo.*/
	private HashMap<String, CachedPassHandler> passKsCachedList = null;
	/** Aviso de uso de clave privada.*/
	private IPassStoreKS noPassWarnKs = null;
	/** Acceso trasparente a claves privadas. */
	private IPassStoreKS noPassNoWarnKs = null;
	/** Acceso a claves privadas para Smart Cards. */
	private IPassStoreKS smartCrdPassKs = null;
	/** Instancia del almacén. */
	private KeyStore ks = null;
	/** Lista de drivers PKCS11. */
	private HashMap<String, String> drvrList = new HashMap<String, String>(); 
	/** Instancias de las pasarelas PKCS11. */
	private MultiPKCS11Store pkcs11s = null;
	/** Implementación del formato de contexto de claves según el alias. */
	private AliasFormat aliasFormat = null;
	
	/**
	 * <p>Crea una instancia relacionándola con un almacén de certificados asociado al fichero de propiedades indicado.</p>
	 * <p>Instanciar el almacén de éste modo, permite que se produzcan cambios persistentes en la configuración.</p>
	 * @param config Fichero con la configuración del almacén
	 * @param auto <code>true</code> si se quiere que se cree el almacén en caso de no existir, <code>false</code> si sólo accede en caso de existir
	 * @return Instancia del almacén con la configuración indicada.
	 * @throws CertStoreException Lanzada cuando no hay acceso al almacén de certificados por no existir fichero de configuración o estar mal formado
	 */
	public static MITyCStore getInstance(final File config, final boolean auto) throws CertStoreException {
		InputStream is = null;
    	if (config != null) {
    		confFile = config;
    		// Se intenta cargar la conf externa pasada como argumento
    		try {
    			is = new FileInputStream(confFile);
    		} catch (FileNotFoundException e) {
    			LOG.error("No se pudo cargar la configuración indicada: " 
    					+ confFile.getPath()
    					+ "\nSe carga la configuración por defecto");
    		}
    	}
    	
    	// Si no se pudo recuperar, se carga la conf interna por defecto
    	if (is == null) {
    		is = KSManagerDialog.class.getResourceAsStream("/MITyC_KS.properties");
    	}
    	
    	return new MITyCStore(is, true);
    	
	}
	
	/**
	 * <p>Crea una instancia relacionándola con un almacén de certificados asociado al fichero de propiedades indicado.</p>
	 * 
	 * @param config InputStream con la configuración del almacén
	 * @throws CertStoreException Lanzada cuando no hay acceso al almacén de certificados por no existir fichero de configuración o estar mal formado
	 */
	public MITyCStore(final InputStream config) throws CertStoreException {
		this(config, false);
	}
	
	/**
	 * <p>Crea una instancia de KeyStore relacionándola con un almacén de certificados 
	 * indicado en las propiedades de cofiguración.</p>
	 * <p>En caso de no existir fichero del almacén indicado, y si el parámetro auto 
	 * es <code>true</code>, se creará uno nuevo en la ruta indicada.</p>
	 * 
	 * El fichero de configuración contiene las claves necesarias para acceder al fichero del almacén y a los diversos drivers para accesos PKCS11
	 * KeyStoreName = Nombre del almacén
	 * PKCS11: {prefijo}.name = Nombre del módulo PCKS11
	 *         {prefijo}.library = Ruta al driver del emisor del token
	 * 
	 * @param config InputStream con la configuración del almacén
	 * @param auto <code>true</code> si se quiere que se cree el almacén en caso de no existir, <code>false</code> si sólo accede en caso de existir
	 * @throws CertStoreException Lanzada cuando no hay acceso al almacén de certificados por no existir fichero de configuración o estar mal formado
	 */
	public MITyCStore(final InputStream config, final boolean auto) throws CertStoreException {
		prop = new Properties();
		try {	
			prop.load(config);
		} catch (IOException e) {
			// No se pudo inicializar el almacén. Compruebe su configuración
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_59), e);
		}
		
		this.autocreate = auto;
		
		init();
	}

	/**
	 * <p>Establece los gestionadores del contraseñas, dependientes del contexto.</p>
	 * <p>Cada vez que se realice un acceso al almacén de certificados que requiera una contraseña 
	 * se pedirá a través del gestionador de contraseñas establecido.</p>  
	 */
	private void initPassHandlers() {
		passKs = new PlainPassHandler();
		passKsCachedList = new HashMap<String, CachedPassHandler>();
		noPassWarnKs = new WarnPassHandler();
		noPassNoWarnKs = new TranslucentPassHandler();
		smartCrdPassKs = new Pkcs11PassHandler();
	}
	
	/**
	 * <p>Obtiene la cadena de certificados asociada al certificado indicado.</p>
	 * 
	 * @param certificate Certificado base de la cadena
	 * @return Cadena de certificación disponible en el almacén relacionado con el certificado provisto. <code>Null</code> si no se encuentra el almacén.
	 * @throws CertStoreException lanzada cuando se produce un error en el acceso al almacén 
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		CertPath cp = null;

		if (certificate == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Faltan parámetros de entrada.");
			}
			return null;
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return null;
		}

		try {
			String alias = ks.getCertificateAlias(certificate);

			if (alias != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("CertPath.- Certificado encontrado en el almacén: " + alias);
				}
				Certificate[] certArray = ks.getCertificateChain(alias);

				ArrayList<X509Certificate> certChain = new ArrayList<X509Certificate>();
				X509Certificate rootCert = (X509Certificate) certArray[0];
				certChain.add(rootCert);

				for (int i = 1; i < certArray.length; i++) {
					certChain.add((X509Certificate) certArray[i]);
				}
				
				cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certChain);
			}
		} catch (KeyStoreException e1) {
			// Error cargando los certificados de firma
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_1), e1);
			return null;
		} catch (CertificateException e) {
			// Error.- No se pudo construir la cadena de confianza
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_2), e);
		} catch (NoSuchProviderException e) {
			// Error.- No se dispone de un proveedor criptográfico
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_3), e);
			return null;
		}

		return cp;
	}

	/**
	 * <p>Obtiene un wrapper de acceso a la clave privada asociada al certificado indicado.</p>
	 * 
	 * @param certificate Certificado del que se requiere la clave privada
	 * @return Clave privada asociada al certificado. <code>Null</code> si no se encuentra.
	 * @throws CertStoreException Lanzada cuando se produce un error en el acceso al almacén
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		if (certificate == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Faltan parámetros de entrada.");
			}
			return null;
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return null;
		}
		
		String alias = null;
		try {
			alias = ks.getCertificateAlias(certificate);
		
			if (alias != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("PrivateKey.- Certificado encontrado en el almacén: " + alias);
				}
				if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
					// Se obtiene el contexto de la clave privada
					KeyStore.PasswordProtection kpp = null;
					aliasFormat = new AliasFormat(alias);
					if (aliasFormat.isProtected()) {
						if (aliasFormat.isPassCached()) {
							CachedPassHandler handler = null;
							synchronized (passKsCachedList) {
								handler = passKsCachedList.get(alias);
								if (handler == null) {
									handler = new CachedPassHandler();
									passKsCachedList.put(alias, handler);
								}
							}
							kpp = new KeyStore.PasswordProtection(handler.getPassword(certificate, null));
						} else {
							kpp = new KeyStore.PasswordProtection(passKs.getPassword(certificate, null));
						}
					} else if (aliasFormat.isMayWarning()) {
						kpp = new KeyStore.PasswordProtection(noPassWarnKs.getPassword(certificate, alias));
					} else {
						kpp = new KeyStore.PasswordProtection(noPassNoWarnKs.getPassword(certificate, alias));
					}
					
					if (kpp.getPassword() == null) {
						// Acceso a clave privada cancelado por el usuario
						LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_81));
						throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_81));
					}
					
					// Se accede a la clave privada
					PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, kpp);
					if (pke != null) {
						return pke.getPrivateKey();
					} else {
						// El certificado no tiene clave privada asociada
						LOG.warn(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_6));
						return null;
					}
				} else {
					// El certificado no tiene clave privada asociada
					LOG.warn(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_6));
					return null;
				}
			} else { // Se busca la clave en los módulos PKCS11
				PrivateKey pk = pkcs11s.getPrivateKey(certificate);
				return pk;
			}
		} catch (KeyStoreException e1) {
			// "Error cargando los certificados de firma
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_1), e1);
			return null;
		} catch (NoSuchAlgorithmException e) {
			// No se pudo recuperar la clave privada. No se reconoce el algoritmo
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_7), e);
			return null;
		} catch (UnrecoverableEntryException e) {
			// Si es una pass cacheada, se resetea
			CachedPassHandler handler = passKsCachedList.get(alias);
			if (handler != null) {
				handler.reset();
			}
			// La clave privada no es extraíble o error en la contraseña
			LOG.warn(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_8));
			return null;
		}
	}

	/**
	 * <p>Se devuelve el provider que da acceso a las capacidades criptográficas del dispositivo relacionado.</p>
	 * 
	 * @param cert Certificado para el que se necesita acceso al provider
	 * @return provider asociado al dispositivo
	 */
	public Provider getProvider(final X509Certificate cert) {
		Provider certProvider = null;
		// Se comprueba si el certificado es PKCS11
		if (pkcs11s != null) {
			certProvider = pkcs11s.getProvider(cert);
		}
		// Si no se encuentra en el módulo PKCS11, se busca en el almacén
		if (certProvider != null) {
			return certProvider;
		} else if (ks != null) {
			// Se devuelve nulo para que se busque la implementación en la lista Security.getProviders()
			return null;//ks.getProvider();
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén de certificados aún no ha sido inicializado");
			}
			return null;
		}
	}

	/**
	 * <p>Devuelve los certificados que tienen asociado clave privada.</p>
	 * 
	 * @return Lista con los certificados que tienen clave privada. <code>Null</code> si no se encuentra el almacén.
	 * @throws CertStoreException Lanzada cuando se produce un error en el acceso al almacén
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return null;
		}
		
		try {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Obteniendo certificados de firma: Tamaño del almacén: " + ks.size());
			}
			Enumeration<String> aliases = ks.aliases();
			String alias = null;
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				if (LOG.isDebugEnabled()) {
					LOG.debug("  - Alias del certificado: " + alias);
				}
				if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
					certs.add((X509Certificate) ks.getCertificate(alias));
				}
			}
		} catch (KeyStoreException e1) {
			// Error cargando los certificados de firma
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_1), e1);
			return null;
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("Lectura.- Accediendo a los módulos PKCS11");
		}
		List<X509Certificate> signCerts11 = pkcs11s.getSignCertificates();
		if (signCerts11 != null) {
			certs.addAll(signCerts11);
		}
		
		return certs;
	}

	/**
	 * <p>Devuelve los certificados de confianza disponibles en el dispositivo externo.</p>
	 * 
	 * @return Lista de certificados de confianza disponibles en el dispositivo. <code>Null</code> si no se encuentra el almacén.
	 * @throws CertStoreException lanzada cuando se produce un error en el acceso al almacén
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return null;
		}
		
		try {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Obteniendo certificados de autenticación.- Tamaño del almacén: " + ks.size());
			}
			Enumeration<String> aliases = ks.aliases();
			String alias = null;
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				if (LOG.isDebugEnabled()) {
					LOG.debug("  - Alias del certificado: " + alias);
				}
				if (ks.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
					certs.add((X509Certificate) ks.getCertificate(alias));
				}
			}
		} catch (KeyStoreException e1) {
			// Error cargando los certificados de autenticación
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_9), e1);
			return null;
		}
		return certs;
	}

	/**
	 * <p>Recupera los certificados que no tienen parte privada asociada en este almacén.</p>
	 * @return Listado de certificados sin clave privada asociada
	 * @throws CertStoreException Lanzado si hay algún problema en la recuperación de certificados
	 **/
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet.");
	}

	/**
	 * <p>Inicializa el acceso al almacén.</p>
	 * 
	 * @throws CertStoreException lanzada si hay algún problema en el acceso al almacén
	 */
	public void init() throws CertStoreException {
		// Se carga el almacén MITyC
		FileInputStream fis = null;
		try {
			ks = KeyStore.getInstance("JCEKS");
		} catch (KeyStoreException e2) {
			// El almacén no está inicializado
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_10), e2);
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("No se pudo instanciar el almacén.");
			}
			return;
		}
		
		// Se establece la interfaz de petición de contraseñas
		initPassHandlers();
		
		// Se recupera la ruta al almacén
		ksURL = prop.getProperty(ConstantsCert.KS_NAME_KEY);
		if (ksURL == null) {
			// Imposible inicializar: No se encuentra la ruta al almacén de certificados
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_11));
		} else {
			ksURL = ksURL.trim();
			prop.remove(ConstantsCert.KS_NAME_KEY);
			if (LOG.isTraceEnabled()) {
				LOG.trace("El almacén se espera en: " + ksURL);
			}
		}

		if (ksURL != null && new File(ksURL).exists() && new File(ksURL).length() != 0) {
			try {
				fis = new FileInputStream(ksURL);
				ks.load(fis, new char[0]); // Con un null como pass, se deshabilita el chequeo de integridad
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (IOException e) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Se reintenta el acceso.- El almacén puede estar protegido con contraseña.");
				}
				try {
					CachedPassHandler handler = null;
					synchronized (passKsCachedList) {
						handler = passKsCachedList.get(ksAlias);
						if (handler == null) {
							handler = new CachedPassHandler();
							passKsCachedList.put(ksAlias, handler);
						}
					}
					//  el almacén MITyC
					fis = new FileInputStream(ksURL);
					ks.load(fis, handler.getPassword(null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_12)));
				} catch (NoSuchAlgorithmException ex) {
					e.printStackTrace();
				} catch (CertificateException ex) {
					e.printStackTrace();
				} catch (IOException ex) {
					if (LOG.isDebugEnabled()) {
						LOG.debug(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_85), ex);
					}
					// No se pudo acceder al almacén. Compruebe su contraseña.
					throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_85));
				}
			} finally {
				if (fis != null) {
					try {
						fis.close();
					} catch (IOException e) { /* No se hace nada */ }
				}
			}
		} else if (autocreate) {
			try {
				ks.load(null);
				saveStore();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (CertificateException e1) {
				e1.printStackTrace();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		} else {
			// El almacén no existe
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_13));
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("Acceso al almacén MITyC exitoso.");
		}
		
	// Apartado para tarjetas criptográficas
		// Se obtienen todas los prefijos para PKCS11 contenidas en la configuración.
		// (las configuraciones PKCS11 se han de ajustar a un modelo <prefijo>.clave)
		Enumeration<Object> keys = prop.keys();
		ArrayList<String> prefijos = new ArrayList<String>();
		while (keys.hasMoreElements()) {
			String key = ((String) keys.nextElement()).trim();
			key = key.substring(0, key.indexOf('.'));
			if (prefijos.contains(key)) {
				continue;
			} else {
				prefijos.add(key);
			}
		}
		
		ConfigMultiPKCS11 config = new ConfigMultiPKCS11();
		for (int i = 0; i < prefijos.size(); ++i) {
			// Se crean las configuraciones en caliente
			try {
				String lib = prop.getProperty(prefijos.get(i) + ".library");
				if (lib != null && new File(lib.trim()) != null && new File(lib.trim()).exists()) {
					lib = lib.trim();
					try {
						config.addSunProvider(prop.getProperty(prefijos.get(i) + ".name").trim(), lib);
					} catch (NoSuchProviderException ex) {
						LOG.error(ex.getMessage());
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
					}
					drvrList.put(prop.getProperty(prefijos.get(i) + ".name").trim(), lib);
				} else {
					// La librería indicada no se encuentra:
					LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_92, lib));
				}
			} catch (MissingResourceException ex) {
				// No se encuentra disponible la configuración específica para esta pasarela. Recuerde crear y configurar el fichero MITyC_KS.properties
				LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_14));
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Cargando pasarelas PKCS11");
		}

		// Se instancia la clase PKCS11 con la configuración requerida
		pkcs11s = new MultiPKCS11Store(config, smartCrdPassKs);
	}

	/**
     * <p>Introduce un certificado de confianza en el almacén de certificados.</p>
     * 
     * @param cert Certificado de confianza
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
	public void addTrustCert(final X509Certificate cert) throws CertStoreException {
		if (cert == null) {
			// Faltan parámetros
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15));
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return;
		}
		
		String newAlias = genNewAlias("SignCert");
		try {
			KeyStore.TrustedCertificateEntry ksEntry = new KeyStore.TrustedCertificateEntry(cert);
			ks.setEntry(newAlias, ksEntry, null);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return;
		}
		
		saveStore();
	}

	/**
	 * <p>Importa un certificado de firma (incluye clave privada) en el almacén.</p>
	 * 
	 * @param pk Clave privada a importar
	 * @param cert Certificado asociado a la clave pública relacionada con la clave privada importada
	 * @param password Contraseña que se aplicará a la clave privada en el almacén
	 * @throws CertStoreException lanzada si hay algún problema en la importación de la clave privada y certificado
	 */
	public void importSignCert(final PrivateKey pk, final X509Certificate cert, final char[] password) throws CertStoreException {
		if (pk == null || cert == null || password == null) {
			// Faltan parámetros
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15));
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return;
		}
		
		// Se pide al usuario que de el contexto de la clave
		PKContextDialog contextDialog = new PKContextDialog(null, this);
		contextDialog.setVisible(true);
		
		String newAlias = genNewAlias(contextDialog.getContext() + "SignCert");
		try {
			KeyStore.PrivateKeyEntry ksEntry = new KeyStore.PrivateKeyEntry(pk, new Certificate[]{cert});
			KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(contextDialog.getPass());
			ks.setEntry(newAlias, ksEntry, pp);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} finally {
			contextDialog.dispose();
		}
		
		saveStore();
	}

	/**
	 * <p>Elimina un certificado del almacén de certificados que esté asociado a una clave privada, junto con la clave privada.</p>
	 * 
	 * @param cert Certificado asociado a una clave privada a eliminar
	 * @throws CertStoreException lanzada si hay algún problema en la eliminación del certificado y de la clave privada
	 */
	public void removeSignCert(final X509Certificate cert) throws CertStoreException {
		if (cert == null) {
			// Faltan parámetros
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15));
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return;
		}
		
		String alias = null;
		try {
			alias = ks.getCertificateAlias(cert);
			if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
				// Se obtiene el contexto de la clave privada para poder acceder
				KeyStore.PasswordProtection kpp = null;
				aliasFormat = new AliasFormat(alias);
				if (aliasFormat.isProtected()) {
					// Si está protegido, se pide la contraseña
					kpp = new KeyStore.PasswordProtection(passKs.getPassword(cert, null));
				} else {
					// En caso contrario, se pide confirmación
					kpp = new KeyStore.PasswordProtection(new DeleteWarnHandler().getPassword(cert, alias));
				}
				
				if (kpp.getPassword() == null) {
					// Acceso a clave privada cancelado por el usuario
					LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_81));
					throw new CertStoreException("Cancelado por el usuario.");
				}
				// Se accede a la clave privada. En caso de no poder acceder, salta una UnrecoverableEntryException
				ks.getEntry(alias, kpp);

				// Se borra el certificado
				ks.deleteEntry(alias);
				saveStore();
			} else if (LOG.isDebugEnabled()) {				
				LOG.debug("No es un certificado de firma asociado a una clave privada.");
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return;
		} catch (UnrecoverableEntryException e) {
			// No se pudo borrar el certificado
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_82));
		} catch (NoSuchAlgorithmException e) {
			// No se pudo borrar el certificado
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_82));
		}
	}

	/**
     * <p>Borra un certificado del almacén de certificados.</p>
     * <p>Si el certificado que se intenta eliminar no es un certificado de confianza, sino de firma, no se deberá eliminar.</p>
     * 
     * @param cert Certificado de confianza a eliminar 
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
	public void removeTrustCert(final X509Certificate cert) throws CertStoreException {		
		if (cert == null) {
			// Faltan parámetros
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15));
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return;
		}
		
		String alias = null;
		try {
			alias = ks.getCertificateAlias(cert);
			if (ks.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
				ks.deleteEntry(alias);
			} else if (LOG.isDebugEnabled()) {
				LOG.debug("No es un certificado de autenticación.");
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return;
		}
		
		saveStore();
	}

	/**
	 * <p>Actualiza el certificado asociado a una clave privada, reemplazando el anterior asociado.</p>
	 *  
	 * @param newCert certificado nuevo a asociar
	 * @throws CertStoreException lanzada si hay algún problema en la actualización del certificado
	 */
	public void updateSignCert(final X509Certificate newCert) throws CertStoreException {		
		if (newCert == null) {
			// Faltan parámetros
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15));
		}
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return;
		}

		try {
			// Se busca en el almacén un certificado con la misma clave pública
			PublicKey pubKey = newCert.getPublicKey();
			String foundAlias = null;
			Iterator <X509Certificate> signCerts = getSignCertificates().iterator();
			X509Certificate signCert = null;
			while (signCerts.hasNext()) {
				signCert = signCerts.next();
				if (pubKey.equals(signCert.getPublicKey())) {
					foundAlias = ks.getCertificateAlias(signCert);
					break;
				}
			}		
			// Se sobreescribe el certificado encontrado	
			if (foundAlias != null) {
				// Si el certificado a actualizar es de firma y se puede borrar...
				if (isDeletable(newCert) && ks.entryInstanceOf(foundAlias, KeyStore.PrivateKeyEntry.class)) {
					ks.setCertificateEntry(foundAlias, newCert);
				} else {
					// El certificado no es actualizable
					throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_93));
				}
			} else {
				// El certificado no existe en el almacén
				throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_16));
			}

			saveStore();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * <p>Indica si un certificado se puede borrar del almacén de certificados.</p>
	 * @param cert .- Certificado a consultar
	 * @return .- <code>true</code> si el certificado el borrable
	 */
	public boolean isDeletable(final X509Certificate cert) {
		boolean borrable = true;
		try {
			borrable = (ks.getCertificateAlias(cert) != null);
		} catch (KeyStoreException ex) {
			borrable = false;
		}
		
		return borrable;
	}
	
	/**
	 * <p>Cierra y salva el almacén de certificados.</p>
	 * 
	 * @return booleano que indica si se completó la tarea satisfactoriamente.
	 * @throws CertStoreException Si se produce un error en la comunicaci�n con el almac�n.
	 */
	private boolean saveStore() throws CertStoreException {
		FileOutputStream fos = null;
		
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return false;
		}

		CachedPassHandler handler = null;
		synchronized (passKsCachedList) {
			handler = passKsCachedList.get(ksAlias);
			if (handler == null) {
				handler = new CachedPassHandler();
				passKsCachedList.put(ksAlias, handler);
			}
		}
		try {
			fos = new FileOutputStream(ksURL);
			ks.store(fos, handler.getPassword(null, null));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_17), e);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} finally {
			if (fos != null) {
				try {
					fos.close();
				} catch (IOException e) {
					throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_17), e);
				}
			}
		}

		return true;
	}
	
	/**
	 * <p>Salva la nueva configuración indicada en el panel de preferencias.</p>
	 * @throws CertStoreException Si no se pudo salvar.
	 */
	protected void saveConf() throws CertStoreException {
		if (confFile == null) {
			// No se pudo salvar la configuración
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_96));
		}
		prop = new Properties();
		
		// Se establece la ruta al almacén
		if (ksURL == null) {
			// Imposible inicializar: No se encuentra la ruta al almacén de certificados
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_11));
		} else {
			prop.setProperty(ConstantsCert.KS_NAME_KEY, ksURL);
			if (LOG.isTraceEnabled()) {
				LOG.trace("El almacén se buscará en: " + ksURL);
			}
		}
		
	// Apartado para tarjetas criptográficas
		// Las configuraciones PKCS11 se han de ajustar a un modelo <prefijo>.clave
		Iterator<Map.Entry<String, String>> contents = drvrList.entrySet().iterator();
    	Map.Entry<String, String> content = null;
    	while (contents.hasNext()) {
    		content = contents.next();
    		// Nombre
    		prop.put(content.getKey().toLowerCase() + ".name",
    				content.getKey());
    		// Driver path
    		prop.put(content.getKey().toLowerCase() + ".library",
    				content.getValue());
    	}
    	
    	FileOutputStream fos;
		try {
			fos = new FileOutputStream(confFile);
			prop.store(fos, null);
		} catch (Exception e) {
			// No se pudo salvar la configuración
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_96), e);
		}
	}
	
	/**
	 * <p>Cambia la contraseña de protección del almacén de certificados.</p>
	 * @param oldPass .- Contiene la antigua contraseña. Es requisito logarse para hacer el cambio
	 * @param newPass .- Contiene la nueva contraseña. <code>char[0]</code> para eliminar el acceso con contraseña
	 * @throws CertStoreException Se lanza si la oldPass es incorrecta. Indica que no se pudo realizar el cambio.
	 */
	public void setNewPass(final char[] oldPass, final char[] newPass) throws CertStoreException {
		if (ks == null) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("El almacén no está inicializado.");
			}
			return;
		}
		
		// Se comprueba que la antigua contraseña sea correcta
		FileInputStream fis = null;
		FileOutputStream fos = null;
		try {
			fis = new FileInputStream(ksURL);
			ks.load(fis, oldPass);
			
			// Si no salta excepción durante el chequeo de integridad, la vieja contraseña
			// es correcta, se procede a introducir la nueva
			fos = new FileOutputStream(ksURL);
			ks.store(fos, newPass);	
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Intento de acceso fallido, compruebe la contraseña.");
			}
			throw new CertStoreException("Intento de acceso fallido, compruebe la contraseña");
		} catch (IOException e) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Intento de acceso fallido, compruebe la contraseña.");
			}
			throw new CertStoreException("Intento de acceso fallido, compruebe la contraseña");
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) { /* No se hace nada */ }
			}
			if (fos != null) {
				try {
					fos.close();
				} catch (IOException e) { /* No se hace nada */ }
			}
		}
	}
	
	/**
	 * <p>Genera un alias nuevo para el KeyStore cargado, a partir de un prefijo.</p>
	 * 
	 * @param prefix Prefijo que tendrá el alias único generado.
	 * @return Alias nuevo para el almacén de certificados. 
	 */
	private String genNewAlias(final String prefix) {
		Random rnd = new Random();
		String alias = prefix + rnd.nextInt(RND_MAX_SIZE);
		
		try {
			while (ks.containsAlias(alias)) {
				alias = prefix + rnd.nextInt(RND_MAX_SIZE);
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return alias;
	}
	
	/**
	 * <p>Devuelve un panel con entradas de configuración del almacén de certificados.</p>
	 * @return El panel construido e inicializado.
	 */
	public JPanel getPreferencesPanel() {				
		return new PreferencesPanel(this, drvrList);
	}
	
	/**
	 * 
	 * @param newDrvrList listado de drivers p11
	 * @throws CertStoreException Lanzada si se produce un error en la configuración del almacén
	 */
	protected void setNewMultiPkcs11(final HashMap<String, String> newDrvrList) throws CertStoreException {
		if (newDrvrList != null) {
			this.drvrList = newDrvrList;
		} else {
			// Faltan parámetros
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_15));
		}
		
		ConfigMultiPKCS11 config = new ConfigMultiPKCS11();
		Iterator<Map.Entry<String, String>> contents = newDrvrList.entrySet().iterator();
    	Map.Entry<String, String> content = null;
    	String lib = null;
    	while (contents.hasNext()) {
    		content = contents.next();
    		lib = content.getValue();
			// Se crean las configuraciones en caliente
			try {
				if (lib != null && new File(lib) != null && new File(lib).exists()) {
					try {
						config.addSunProvider(content.getKey(), lib);
					} catch (NoSuchProviderException ex) {
						LOG.error(ex.getMessage());
						if (LOG.isDebugEnabled()) {
							LOG.debug("", ex);
						}
					}
				} else {
					// La librería indicada no se encuentra:
					LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_92, lib));
				}
			} catch (MissingResourceException ex) {
				// No se encuentra disponible la configuración específica para esta pasarela. Recuerde crear y configurar el fichero MITyC_KS.properties
				LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_14));
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Cargando pasarelas PKCS11");
		}

		// Se instancia la clase PKCS11 con la configuración requerida
		pkcs11s = new MultiPKCS11Store(config, smartCrdPassKs);
	}
	
	/**
	 * <p>Clase que construye un panel de configuración para las preferencias del MITyCKeyStrore.</p>
	 * 
	 */
	private class PreferencesPanel extends JPanel {
			
		/** Ancho del panel. */
		private static final int WIDTH = 350;
		/** Alto del diálogo. */
		private static final int HEIGHT = 265;
		
		/** Lista de drivers PKCS11. */
		private HashMap<String, String> drivrList = null;

		/** Instancia del almacén. */
		private MITyCStore store = null;
		
		/**
		 * <p>Constructor. Carga el panel de configuración del almacén.</p> 
		 * @param keyStore instancia del almacén de certificados
		 * @param drvrList lista de drivers para las pasarelas PKCS#11
		 */
	    public PreferencesPanel(final MITyCStore keyStore, final HashMap<String, String> drvrList) {    	
	    	super();
	    	this.store = keyStore;
	    	this.drivrList = drvrList;
	    	init();
	    }
		
		/**
	     * <p<Inicialización de los componentes visuales.</p>
	     */
		private void init() {
			// Preferencias
			setBorder(BorderFactory.createTitledBorder(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_90)));
	    	
	    	tabs = new JTabbedPane();
	    	
	    // Pestaña de cambio de contraseña
	    	storePass = new JPanel();
	    	
	    	// Contraseña antigua
	    	oldPassLabel = new JLabel(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_87));
	    	oldPassLabel.setHorizontalAlignment(SwingConstants.RIGHT);
	    	oldPassField = new JPasswordField();
	    	// Contraseña nueva
	    	newPassLabel = new JLabel(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_88));
	    	newPassLabel.setHorizontalAlignment(SwingConstants.RIGHT);
	    	newPassField = new JPasswordField();
	    	// Sin contraseña
	    	noPassCheck = new JCheckBox(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_89));
	    	noPassCheck.addItemListener(new ItemListener() {
				public void itemStateChanged(final ItemEvent e) {
					noPassActionPerformed(e);
				}
	        });
	        
	        aceptarButton = new JButton();
	        
	        setLayout(new GridBagLayout());
	        storePass.setLayout(new GridBagLayout());
	        
	        // Layout      
			GridBagConstraints oldPassLblConstraints = new GridBagConstraints();
			oldPassLblConstraints.gridx = 0;
			oldPassLblConstraints.gridy = 0;
			oldPassLblConstraints.insets = new Insets(5, 10, 3, 3);
			oldPassLblConstraints.anchor = GridBagConstraints.EAST;
			storePass.add(oldPassLabel, oldPassLblConstraints);
			
			GridBagConstraints oldPassFldConstraints = new GridBagConstraints();
			oldPassFldConstraints.gridx = 1;
			oldPassFldConstraints.gridy = 0;
			oldPassFldConstraints.fill = GridBagConstraints.HORIZONTAL;
			oldPassFldConstraints.weightx = 1.0;
			oldPassFldConstraints.gridwidth = 2;
			oldPassFldConstraints.insets = new Insets(5, 3, 3, 20);
			storePass.add(oldPassField, oldPassFldConstraints);
			
			GridBagConstraints newPassLblConstraints = new GridBagConstraints();
			newPassLblConstraints.gridx = 0;
			newPassLblConstraints.gridy = 1;
			newPassLblConstraints.insets = new Insets(5, 10, 3, 3);
			newPassLblConstraints.anchor = GridBagConstraints.EAST;
			storePass.add(newPassLabel, newPassLblConstraints);
			
			GridBagConstraints newPassFldConstraints = new GridBagConstraints();
			newPassFldConstraints.gridx = 1;
			newPassFldConstraints.gridy = 1;
			newPassFldConstraints.weightx = 1.0;
			newPassFldConstraints.fill = GridBagConstraints.HORIZONTAL;
			newPassFldConstraints.insets = new Insets(5, 3, 3, 20);
			storePass.add(newPassField, newPassFldConstraints);
			
			GridBagConstraints noPassCheckConstraints = new GridBagConstraints();
			noPassCheckConstraints.gridx = 0;
			noPassCheckConstraints.gridy = 2;
			noPassCheckConstraints.insets = new Insets(5, 10, 3, 10);
			noPassCheckConstraints.gridwidth = 3;
			noPassCheckConstraints.anchor = GridBagConstraints.CENTER;
			storePass.add(noPassCheck, noPassCheckConstraints);
			
		// Panel de administración de pasarelas PKCS11
			pkcs11Admon = new JPanel();
			
			// Tabla de drivers 
			driversTbl = new JTable();
			driversTbl.setDefaultRenderer(Object.class, new CertCellRenderer());
			driversTbl.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			driversTbl.setPreferredScrollableViewportSize(new Dimension(500, 200));
			driversTbl.setModel(new DriverTblModel(this.drivrList));
			driversTbl.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
			driversTbl.getColumnModel().getColumn(1).setPreferredWidth(250);
			driversTbl.getColumnModel().getColumn(1).setMaxWidth(250);
			driversTbl.getColumnModel().getColumn(1).setMinWidth(250);
			driversTbl.getColumnModel().getColumn(1).setWidth(250);
			
			driversScroll = new JScrollPane(driversTbl);
			
			addDrvrButton = new JButton();
			addDrvrButton.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_71)); // Añadir
			addDrvrButton.addActionListener(new ActionListener() {
	            public void actionPerformed(final ActionEvent evt) {
	            	addDriverBtnActionPerformed();
	            }
	        });
			
			delDrvrButton = new JButton();
			delDrvrButton.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_70)); // Borrar
			delDrvrButton.addActionListener(new ActionListener() {
	            public void actionPerformed(final ActionEvent evt) {
	            	delDriverBtnActionPerformed();
	            }
	        });
	        
	        // Layout
			pkcs11Admon.setLayout(new GridBagLayout());
			
			GridBagConstraints drvTblConstraints = new GridBagConstraints();
			drvTblConstraints.gridx = 0;
			drvTblConstraints.gridy = 0;
			drvTblConstraints.fill = GridBagConstraints.HORIZONTAL;
			drvTblConstraints.weightx = 1.0;
			drvTblConstraints.gridwidth = 4;
			drvTblConstraints.ipady = 50;
			drvTblConstraints.insets = new Insets(5, 5, 10, 5);
			pkcs11Admon.add(driversScroll, drvTblConstraints);
			
			GridBagConstraints addDrvBtnConstraints = new GridBagConstraints();
			addDrvBtnConstraints.gridx = 0;
			addDrvBtnConstraints.gridy = 1;
			addDrvBtnConstraints.gridwidth = 1;
			addDrvBtnConstraints.insets = new Insets(5, 55, 5, 5);
			pkcs11Admon.add(addDrvrButton, addDrvBtnConstraints);

			GridBagConstraints delDrvBtnConstraints = new GridBagConstraints();
			delDrvBtnConstraints.gridx = 3;
			delDrvBtnConstraints.gridy = 1;
			delDrvBtnConstraints.gridwidth = 1;
			delDrvBtnConstraints.insets = new Insets(5, 30, 5, 5);
			pkcs11Admon.add(delDrvrButton, delDrvBtnConstraints);
			
			// Pestañas
	    	tabs.addTab(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_20), storePass); // Contraseña
	    	if (confFile != null) {
	    		tabs.addTab("SmartCards", pkcs11Admon);
	    	}
			
			// Panel Principal		
	        GridBagConstraints tabsConstraints = new GridBagConstraints();
	        tabsConstraints.gridx = 0;
	        tabsConstraints.gridy = 0;
	        tabsConstraints.fill = GridBagConstraints.BOTH;
	        tabsConstraints.weightx = 1.0;
	        tabsConstraints.weighty = 1.0;
	        add(tabs, tabsConstraints);
	        
	        GridBagConstraints aceptarButtonConstraints = new GridBagConstraints();
			aceptarButtonConstraints.gridx = 0;
			aceptarButtonConstraints.gridy = 1;
			aceptarButtonConstraints.anchor = GridBagConstraints.CENTER;
			aceptarButtonConstraints.insets = new Insets(10, 20, 10, 20);
	        // Aceptar
			aceptarButton.setText(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_ACCEPT));
	        aceptarButton.addActionListener(new ActionListener() {
	            public void actionPerformed(final ActionEvent evt) {
	                jAceptarButtonActionPerformed();
	            }
	        });
	        add(aceptarButton, aceptarButtonConstraints);

	        setSize(WIDTH, HEIGHT);
	    }
		
		/**
		 * <p>Activa o desactiva la posibilidad de introducir una nueva contraseña.</p>
		 * @param e Evento de selección
		 */
		private void noPassActionPerformed(final ItemEvent e) {
			boolean passEnabled = (ItemEvent.DESELECTED == e.getStateChange());
			newPassLabel.setEnabled(passEnabled);
			newPassField.setEnabled(passEnabled);
			
			repaint();
		}
		
		/**
		 * <p>Añade un driver PKCS 11 a la lista de drivers, si el path no existe ya en la lista.</p>
		 */
		private void addDriverBtnActionPerformed() {
			String origen = System.getProperty("user.home");
        	String osName = System.getProperty("os.name");
            if (!osName.toLowerCase().startsWith("win")) { // Para Linux y Mac
        		origen = "/usr/Library/OpenSC/bin/opensc-pkcs11.so";
        	}
            
        	// Se pide la ruta donde se encuentra el driver a añadir
        	JFileChooser chooser = new JFileChooser();
    		chooser.setDialogTitle(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_97)); // Ruta al driver PKCS#11
    	    chooser.setSelectedFile(new File(origen));
    	    int returnVal = chooser.showOpenDialog(getTopLevelAncestor());
    	    if (returnVal == JFileChooser.APPROVE_OPTION) {
    	    	origen = chooser.getSelectedFile().getAbsolutePath();
    	    } else {
    	    	LOG.debug("Cancelado por el usuario.");
    	    	return;
    	    }
        	
        	if (origen == null || !origen.contains(".")) {		
        		return;
        	} else {
        		int initialPoint = origen.lastIndexOf(File.separator) + 1;
        		if (initialPoint == -1) {
        			initialPoint = 0;
        		}
        		int lastPoint = origen.lastIndexOf(".");
        		if (lastPoint == -1) {
        			lastPoint = origen.length();
        		}
        		
        		if (!drvrList.containsValue(origen)) { // Se añade sólo si no existe en la lista
        			drvrList.put(origen.substring(initialPoint, lastPoint), origen);
        			((DriverTblModel) driversTbl.getModel()).addRow(origen.substring(initialPoint, lastPoint), origen);
        			driversTbl.addNotify();
        		}
        	}
		}
		
		/**
		 * <p>Elimina un driver PKCS 11 de la lista.</p>
		 */
		private void delDriverBtnActionPerformed() {
			int selIndex = driversTbl.getSelectedRow();
        	if (selIndex >= 0) {
        		String key = (String) driversTbl.getModel().getValueAt(selIndex, 0);
        		drivrList.remove(key);
        		((DriverTblModel) driversTbl.getModel()).removeRow(selIndex);
        	}
		}
	    
	    /**
	     * <p>Cierra la ventana donde se muestran los datos del certificado seleccionado.</p>
	     */
	    private void jAceptarButtonActionPerformed() {
	    	
	    	if (oldPassField.getPassword() != null && oldPassField.getPassword() != new char[0]) {
	    		char[] newPass = new char[0];
	    		if (!noPassCheck.isSelected()) {
	    			newPass = newPassField.getPassword();
	    		}
	    		try {
					store.setNewPass(oldPassField.getPassword(), newPass);
				} catch (CertStoreException e) {
					JOptionPane.showMessageDialog(this,
							// No se pudo cambiar la contraseña.\nCompruebe la contraseña antigua
							I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_91),
							I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),
	    					JOptionPane.ERROR_MESSAGE);
					oldPassField.setText("");
				}
	    	}
	    	
	    	// Se salva la lista de drivers si existe un fichero de configuración 
	    	if (drivrList != null) {
	    		if (confFile != null) {
	    			try {
	    				store.setNewMultiPkcs11(this.drivrList);				
	    				store.saveConf();
	    			} catch (CertStoreException e) {
	    				JOptionPane.showMessageDialog(this,
	    						e.getMessage(),
	    						I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_77),
	    						JOptionPane.ERROR_MESSAGE);
	    				return;
	    			}
	    		}
	    	}
	    	
	    	setVisible(false);
	    	if (getTopLevelAncestor() != null && getTopLevelAncestor() instanceof JDialog) {
	    		getTopLevelAncestor().setVisible(false);
	    		((JDialog) getTopLevelAncestor()).dispose();
	    	}
	    }
	    
		//Declaración de los componentes visuales.
	    /** Pestañas. */
	    private JTabbedPane tabs = null;
	    /** Botón aceptar. */
		private JButton aceptarButton = null;
		
		/** Panel principal para la administración de contraseña. */
		private JPanel storePass = null;
		/** Etiqueta "Contraseña antigua". */
		private JLabel oldPassLabel = null;
		/** Campo para la antigua contraseña. */
		private JPasswordField oldPassField = null;
		/** Etiqueta "Contraseña nueva". */
		private JLabel newPassLabel = null;
		/** Campo para la nueva contraseña. */
		private JPasswordField newPassField = null;
		/** Chack para deshabilitar la contraseña de acceso. */
		private JCheckBox noPassCheck = null;
		
		/** Panel principal para la administración de pasarelas PKCS11. */
		private JPanel pkcs11Admon = null;
		/** ScrollPane para el panel de certificados de firma. */
		private JScrollPane driversScroll = null;	
		/** Tabla de drivers para las pasarelas PKCS11. */
		private JTable driversTbl = null;
		 /** Botón añadir. */
		private JButton addDrvrButton = null;
		 /** Botón eliminar. */
		private JButton delDrvrButton = null;
	}
	
	/**
	 * <p>Clase interna encargada de implementar el formato de control de claves a través del alias.</p>
	 * 
	 */
	protected class AliasFormat {
		
		/** Indica que la clave privada asociada está protegida con contraseña. */
		private final char keyProtected = 'p';
		/** Indica que la clave privada no está protegida. */
		private final char keyUnprotected = 'u';
		
		/** Variable de control. la clave está protegida */
		private boolean isProtected = true;
		/** Variable de control. Indica que la password está cacheada */
		private boolean isPassCached = false;
		/** Variable de control. Se avisa cuanso se va a utilizar la clave privada. */
		private boolean mayWarning = false;
		
		/**
		 * <p>Constructor. Decodifica el alias para obtener el contexto para la clave privada.</p>
		 * @param alias .- Alias a decodificar. Si el alias no se ajusta al formato, por defecto se 
		 *      toma que la clave privada está protegida, sin cacheo, y sin aviso de uso.
		 */
		public AliasFormat(String alias) {
			if (alias == null || alias.length() <= 0) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("El alias no cumple con el formato");
				}
				return;
			}
			char[] aliasArray = alias.toCharArray();
			if (keyProtected == aliasArray[0]) {
				if ('0' == aliasArray[1]) {
					isProtected = true;
					isPassCached = false;
					mayWarning = false;
				} else if ('1' == aliasArray[1]) {
					isProtected = true;
					isPassCached = true;
					mayWarning = false;
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("El alias no cumple con el formato");
					}
					return;
				}
			} else if (keyUnprotected == aliasArray[0]) {
				if ('0' == aliasArray[1]) {
					isProtected = false;
					isPassCached = false;
					mayWarning = false;
				} else if ('1' == aliasArray[1]) {
					isProtected = false;
					isPassCached = false;
					mayWarning = true;
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("El alias no cumple con el formato");
					}
					return;
				}
			}
		}
		
		/**
		 * <p>Generador de prefijos para alias, según el formato, indicando el contexto deseado.</p> 
		 * 
		 * @param isPro <code>true</code> indica que la clave rpivada está protegida. 
		 * @param isCached <code>true</code> indica que la pass se chachea (sólo se pide 1 vez).
		 * @param mayWarn <code>true</code> indica que se alerta sobre el uso de la clave.
		 * @return Prefijo generado segun el contexto indicado
		 */
		public String genAliasPrefix(final boolean isPro, final boolean isCached, final boolean mayWarn) {
			StringBuffer sb = new StringBuffer("");
			
			if (isPro) {
				sb.append(keyProtected);
				if (isCached) {
					sb.append('1');
				} else {
					sb.append('0');
				}
			} else {
				sb.append(keyUnprotected);
				if (mayWarn) {
					sb.append('1');
				} else {
					sb.append('0');
				}
			}
			
			// Margen para futuras extensiones del formato
			sb.append("00");
			
			return sb.toString();
		}
		
		/**
		 * <p>Indica si clave privada está protegida con contraseña.</p>
		 * @return <code>true</code> si está protegido
		 */
		public boolean isProtected() {
			return isProtected;
		}
		
		/**
		 * <p>Indica si la contraseña será chacheada para futuros usos.</p>
		 * @return <code>true</code> si la contraseña se cachea
		 */
		public boolean isPassCached() {
			return isPassCached;
		}
		
		/**
		 * <p>Indica si el uso de la clave es alertado.</p>
		 * @return <code>true</code> si el uso debe ser alertado
		 */
		public boolean isMayWarning() {
			return mayWarning;
		}
	}
}
