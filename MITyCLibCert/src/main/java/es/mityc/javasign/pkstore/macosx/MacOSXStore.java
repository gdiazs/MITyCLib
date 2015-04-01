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
package es.mityc.javasign.pkstore.macosx;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;
import es.mityc.javasign.pkstore.NullPassStorePK;
import es.mityc.javasign.pkstore.keystore.KSStore;
import es.mityc.javasign.pkstore.mozilla.MozillaStoreUtils;

/**
 * <p>Wrapper para permitir utilizar el almacén de claves de Apple en los componentes de firma.</p>
 * 
 */
public class MacOSXStore implements IPKStoreManager {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MozillaStoreUtils.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Nombre del provider del almacén de Mac OS X. */
	private static final String APPLE_KEYSTORE = "Apple";
	/** Nombre del provider criptográfico de firma de Mac OS X. */
	private static final String SUN_KEYSTORE = "SunRsaSign";
	
	/** Cadena vacía. */
	private static final char[] APPLE_EMPTY_STRING = "-".toCharArray();
	
	/** Store del tipo KeyStore que realmente realiza los accesos al almacén de MacOS X. */
	private IPKStoreManager pkStore;
	
	/**
	 * <p>Constructor.</p>
	 * @throws CertStoreException Lanzada si no se puede acceder al almacén de claves de Apple
	 */
	public MacOSXStore() throws CertStoreException {
		this(new NullPassStorePK());
	}

	/**
	 * <p>Constructor.</p>
	 * 
	 * @param passwordHandler Manejador que servirá para recuperar las claves del KeyStore
	 * @throws CertStoreException Lanzada si no se puede acceder al almacén de claves de Apple
	 */
	public MacOSXStore(IPassStoreKS passwordHandler) throws CertStoreException {
		try {
			KeyStore appleKs = KeyStore.getInstance("KeychainStore", APPLE_KEYSTORE);
			appleKs.load(null, null);
			pkStore = new KSStore(appleKs, passwordHandler, APPLE_EMPTY_STRING);
			
			if (LOG.isDebugEnabled()) {
				Iterator<Service> services = Security.getProvider(SUN_KEYSTORE).getServices().iterator();
				LOG.debug("Servicios disponibles: ");
				while (services.hasNext()) {
					Service ser = services.next();
					LOG.debug(ser);
					LOG.debug("Algoritmo disponible: " + ser.getAlgorithm());
				}				
			}
			
			if (LOG.isDebugEnabled()) {
				Iterator<Service> services = Security.getProvider(APPLE_KEYSTORE).getServices().iterator();
				LOG.debug("Servicios disponibles: ");
				while (services.hasNext()) {
					Service ser = services.next();
					LOG.debug(ser);
					LOG.debug("Algoritmo disponible: " + ser.getAlgorithm());
				}				
			}
		} catch (NoSuchProviderException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MACOSX_1, ex.getMessage()), ex);
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MACOSX_1, ex.getMessage()), ex);
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MACOSX_1, ex.getMessage()), ex);
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MACOSX_1, ex.getMessage()), ex);
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MACOSX_1, ex.getMessage()), ex);
		}
	}
	
	/**
	 * <p>Devuelve el Provider que permite trabajar con el KeyStore configurado.</p>
     * @param cert Certificado para el que se necesita acceso al provider
	 * @return Provider asociado al KeyStore
	 */
	public Provider getProvider(final X509Certificate cert) {
		return Security.getProvider(SUN_KEYSTORE);
	}
	
	/**
	 * <p>Devuelve la cadena de certificación de un certificado.</p>
	 * @param certificate certificado del que construir la cadena
	 * @return Cadena de certificación
	 * @throws CertStoreException Lanzado si hay algún problema en la construcción de la cadena
	 * @see es.mityc.javasign.pkstore.keystore.KSStore#getCertPath(X509Certificate)
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		return (pkStore != null) ? pkStore.getCertPath(certificate) : null;
	}
	
	/**
	 * <p>Devuelveun proxy a la clave privada asociada al certificado indicado.</p>
	 * @param certificate certificado del que se consulta la clave privada
	 * @return clave privada asociada al certificado
	 * @throws CertStoreException Lanzado si hay algún problema al intentar recuperar la clave privada o no existe
	 * @see es.mityc.javasign.pkstore.keystore.KSStore#getPrivateKey(X509Certificate)
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		return (pkStore != null) ? pkStore.getPrivateKey(certificate) : null;
	}
	
	/**
	 * <p>Recupera los certificados que pueden firmar (disponen de clave privada) de este almacén.</p>
	 * @return Listado de certificados que pueden firmar
	 * @throws CertStoreException Lanzado si hay algún problema en la recuperación de certificados
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		return (pkStore != null) ? pkStore.getSignCertificates() : null;
	}
	
	/**
	 * <p>Recupera los certificados de confianza de este almacén.</p>
	 * @return Listado de certificados de confianza
	 * @throws CertStoreException Lanzado si hay algún problema en la recuperación de certificados
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		return (pkStore != null) ? pkStore.getTrustCertificates() : null;
	}
	
	/**
	 * <p>Recupera los certificados que no tienen parte privada asociada en este almacén.</p>
	 * @return Listado de certificados sin clave privada asociada
	 * @throws CertStoreException Lanzado si hay algún problema en la recuperación de certificados
	 */	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		return (pkStore != null) ? pkStore.getPublicCertificates() : null;
	}

}
