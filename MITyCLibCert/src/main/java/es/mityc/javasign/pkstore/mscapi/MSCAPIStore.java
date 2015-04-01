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
package es.mityc.javasign.pkstore.mscapi;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.exception.CopyFileException;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;
import es.mityc.javasign.pkstore.keystore.KeyTool;
import es.mityc.javasign.utils.CopyFilesTool;
import es.mityc.javasign.utils.ProvidersUtil;

/**
 * <p>Wrapper para permitir utilizar los servicios de MSCAPI (acceso a los servicios criptográficos de Microsoft en Windows).</p> 
 * <p>Para proporcionar los servicios se intentará utilizar en primer lugar el proveedor de seguridad SunMSCAPI-MITyC, en el caso de que 
 * dicho proveedor esté en el classpath. En el caso de que el proveedor SunMSCAPI-MITyC no esté disponible, se utilizará el proveedor
 * SunMSCAPI.</p> 
 * 
 */

public class MSCAPIStore implements IPKStoreManager {
	
    /** Localizaciones posibles de los almacenes. */
    public enum LocationStoreType { CurrentUser, LocalMachine };
    
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MSCAPIStore.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
    /** Nombre del almacén del usuario actual donde están los certificados personales. */
	private static final String MY_STORE = "Windows-MY";
    /** Nombre del almacén del usuario actual donde están los certificados de entidades raíz de confianza de windows. */
	private static final String ROOT_STORE = "Windows-ROOT";
    /** 
     * Nombre del almacén del usuario actual donde se encuentran las autoridades de certificación de windows. 
     * A este almacén sólo se podrá acceder si se utiliza el proveedor SunMSCAPI modificado por el MITyC 
     */
    private static final String CA_STORE = "Windows-CA";

    /** Nombre del almacén de la cuenta del equipo donde están los certificados personales. */
    private static final String LOCAL_MACHINE_MY_STORE = "Windows-LocalMachine-MY";
    /** Nombre del almacén de la cuenta del equipo donde están los certificados de entidades raíz de confianza de windows. */
    private static final String LOCAL_MACHINE_ROOT_STORE = "Windows-LocalMachine-ROOT";
    /** Nombre del almacén de la cuenta del equipo donde se encuentran las autoridades de certificación de windows. */
    private static final String LOCAL_MACHINE_CA_STORE = "Windows-LocalMachine-CA";

	/** Nombre del provider de acceso a servicios criptográficos sobre windows. */
	private static final String SUN_MSCAPI_PROVIDER = "SunMSCAPI";
    /** Clase que implementa el key store para el proveedor MSCAPI modificado por MITyC. */
    private static final String SUN_MSCAPI_MITYC_KEY_STORE_CLASS = "es.mityc.javasign.pkstore.mscapi.mityc.KeyStore";
	/** Clase que implementa el provider MSCAPI modificado por MITyC. */
	private static final String SUN_MSCAPI_MITYC_PROVIDER_CLASS = "es.mityc.javasign.pkstore.mscapi.mityc.SunMSCAPI_MITyC";

	/** Indica si la parte nativa se ha inicializado. */
    private static boolean initialized = false;

	/** Manejador de las contraseñas. */
	private IPassStoreKS passHandler;

	/** Provider a utilizar. */
    private Provider provider;

    /** Localización del almacén. */
    private LocationStoreType locationStore;
    
    /** Indica si se está utilizando el provider modificado por MITyC */
    private boolean usingSunMSCAPIMITyC = false;
    
	/**
	 * <p>PassHandler que no da acceso a ninguna contraseña.</p>
	 * 
	 */
	public class NullPassStorePK implements IPassStoreKS {
		/**
		 * <p>Devuelve una contraseña vacía en cualquier consulta.</p>
		 * @param certificate Certificado al que se accede
		 * @param alias alias al que se accede
		 * @return Contraseña vacía
		 * @see es.mityc.javasign.pkstore.IPassStoreKS#getPassword(java.security.cert.X509Certificate, java.lang.String)
		 */
		public char[] getPassword(final X509Certificate certificate, final String alias) {
			return new char[0];
		}
	}
	
    /**
     * <p>Copia la librería externa DLL al directorio temporal.</p>
     * @throws CopyFileException lanzada cuando no se puede copiar la librería nativa
     */
    private synchronized void copyLibrary(boolean retry) throws CopyFileException {
    	LOG.debug("Copiando librerías: " + initialized);
        if (!initialized) {
        	CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_SUNMSCAPIMITYC_PROPERTIES, this.getClass().getClassLoader());
        	if (retry) {
        		String random = new Long(System.currentTimeMillis()).toString();
     			cft.copyFilesOS(null, ConstantsCert.CP_SUNMSCAPIMITYC, true, random);
        	} else {
        		cft.copyFilesOS(null, ConstantsCert.CP_SUNMSCAPIMITYC, true);
        	}
        	initialized = true;
        }
    }

    /**
     * <p>Constructor. Accederá al almacén del usuario actual.</p>
     * 
     * @param passStoreHandler Manejador que servirá para obtener acceso a certificados/claves de los almacenes de Windows. Si se indica
     *      <code>null</code> no se intentará utilizar ninguna contraseña al acceder a los almacenes.
     * @throws CertStoreException lanzada cuando no se puede acceder al almacén de windows mediante SunMSCAPI
     */
    public MSCAPIStore(final IPassStoreKS passStoreHandler) throws CertStoreException {
        this(passStoreHandler, LocationStoreType.CurrentUser);
    }
    
    /**
	 * <p>Constructor indicando la localización del almacén.</p>
	 * 
	 * @param passStoreHandler Manejador que servirá para obtener acceso a certificados/claves de los almacenes de Windows. Si se indica
	 * 		<code>null</code> no se intentará utilizar ninguna contraseña al acceder a los almacenes.
	 * @param location Localizacion del almacén
	 * @throws CertStoreException lanzada cuando no se puede acceder al almacén de windows mediante SunMSCAPI
	 */
	public MSCAPIStore(final IPassStoreKS passStoreHandler, LocationStoreType location) throws CertStoreException {
	    this.locationStore = location;
	    try {
	        /*
             * Primero comprobamos que exista la clase del keyStore de la
             * paquetería correspondiente al provider MSCAPI modificado por MITyC
             */
            Class.forName(SUN_MSCAPI_MITYC_KEY_STORE_CLASS);
            copyLibrary(false);
            Class< ? > sunMscapiMITyCProviderClass = Class.forName(SUN_MSCAPI_MITYC_PROVIDER_CLASS);
            Constructor< ? > constructor = sunMscapiMITyCProviderClass.getConstructor(new Class[0]);
            provider = (Provider) constructor.newInstance(new Object[0]);
            LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_9));
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex);
            }
            try {
            copyLibrary(true);
            Class< ? > sunMscapiMITyCProviderClass = Class.forName(SUN_MSCAPI_MITYC_PROVIDER_CLASS);
            Constructor< ? > constructor = sunMscapiMITyCProviderClass.getConstructor(new Class[0]);
            provider = (Provider) constructor.newInstance(new Object[0]);
            LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_9));
            } catch (Throwable e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_8, e.getMessage()), e);
                }
            }
        }
        /*
         * Si no se ha podido crear el provider MSCAPI modificado por MITyC, se
         * intenta con el provider MSCAPI original de Sun
         */
        if (provider == null) {
            provider = Security.getProvider(SUN_MSCAPI_PROVIDER);
            if (provider == null) {
                throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_7));
            } else {
            	ProvidersUtil.registerProvider(provider.getClass().getName());
            	LOG.info(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_10));
            }
        } else {
            usingSunMSCAPIMITyC = true;
        }
		if (passStoreHandler == null) {
			this.passHandler = new NullPassStorePK();
		} else {
			this.passHandler = passStoreHandler;
		}
	}

	/**
	 * <p>Obtiene la cadena de certificados asociada a un certificado específico.</p>
	 * <p>No implementado</p>
	 * @param certificate Certificado del que se requiere la cadena
	 * @return Lanza la excepción UnsupportedOperationException
	 * @throws CertStoreException No se lanza nunca
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Obtiene acceso a la clave privada de un certificado específico.</p>
	 * 
	 * @param certificate Certificado del que se quiere su clave privada
	 * @return Clave privada
	 * @throws CertStoreException Lanzada cuando no consigue acceso a la clave por los siguientes motivos:
	 * 			<ul>
	 * 				<li>fallo de contraseña</li>
	 * 				<li>ausencia de certificado en el keystore</li>
	 * 				<li>ausencia de clave (está el certificado pero no tiene clave asociada, es un TrustedCertificate)</li>
	 * 			</ul>
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		try {
		    String storeName = null;
		    switch (this.locationStore) {
	            case CurrentUser:
	                storeName = MY_STORE;
	                break;
	            case LocalMachine:
	                storeName = LOCAL_MACHINE_MY_STORE;
	            default:
	                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, provider);
			ks.load(null, null);
			PrivateKey resultado = KeyTool.findPrivateKey(ks, certificate, passHandler);
			return resultado;
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}

	/**
	 * <p>Devuelve el Provider que permite trabajar con los servicios criptográficos de MSCAPI.</p>
     * @param certificate Certificado para el que se necesita acceso al provider
	 * @return Provider asociado al MSCAPI
	 */
	public Provider getProvider(final X509Certificate certificate) {
		return provider;
	}

	/**
	 * <p>Recupera los certificados que pueden firmar contenidos disponibles según MSCAPI.</p>
	 * 
	 * @return Listado de certificados con clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con MSCAPI
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
	            case CurrentUser:
	                storeName = MY_STORE;
	                break;
	            case LocalMachine:
	                storeName = LOCAL_MACHINE_MY_STORE;
	            default:
	                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, provider);
			ks.load(null, null);
			return KeyTool.getCertificatesWithKeys(ks);
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}
	
	/**
	 * <p>Recupera los certificados públicos disponibles según MSCAPI.</p>
	 * 
	 * @return Listado de certificados sin clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con MSCAPI
	 */
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
	            case CurrentUser:
	                storeName = MY_STORE;
	                break;
	            case LocalMachine:
	                storeName = LOCAL_MACHINE_MY_STORE;
	            default:
	                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, provider);
			ks.load(null, null);
			return KeyTool.getCertificatesWithoutKeys(ks);
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}

	/**
	 * <p>Recupera los certificados de confianza según MSCAPI. Los certificados serán la suma
	 * de los existentes en los almacenes ROOT y CA.</p>
	 * 
	 * @return Listado de certificados de confianza
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con MSCAPI
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
	            case CurrentUser:
	                storeName = ROOT_STORE;
	                break;
	            case LocalMachine:
	                storeName = LOCAL_MACHINE_ROOT_STORE;
	            default:
	                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, provider);
			ks.load(null, null);
			ArrayList<X509Certificate> lista = new ArrayList<X509Certificate>();
			lista.addAll(KeyTool.getTrustCertificates(ks));
            
			if (usingSunMSCAPIMITyC) {
			    switch (this.locationStore) {
			        case CurrentUser:
			            storeName = CA_STORE;
			            break;
			        case LocalMachine:
			            storeName = LOCAL_MACHINE_CA_STORE;
			        default:
			            break;
			    }
			    ks = KeyStore.getInstance(storeName, provider);
			    ks.load(null, null);
			    lista.addAll(KeyTool.getTrustCertificates(ks));
			}
			return lista;
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}
}
