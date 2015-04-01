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
package es.mityc.javasign.pkstore.dniejava;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.CardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KSStore;

/**
 * <p>Almacén de certificados propio basado en un almacén de certificados software más acceso a componentes mediante pkcs#11.</p> 
 *  
 */
public class DNIeJavaStore implements IPKStoreManager {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(DNIeJavaStore.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	private static final String DNI_KEYSTORE = "DNI";
	private static final String DNI_PROVIDER = "DNIeJCAProvider";
    private IPKStoreManager pkStore = null;
	
	public DNIeJavaStore() throws CertStoreException {
	    try{
    	    Provider p = new DnieProvider();
    	    Security.addProvider(p);
    	    KeyStore ks = KeyStore.getInstance(DNI_KEYSTORE);
    	    ks.load(null, null);
    	    
    	    pkStore = new KSStore(ks, null, "".toCharArray());
            if (LOG.isDebugEnabled()) {
                Iterator<Service> services = Security.getProvider(DNI_PROVIDER).getServices().iterator();
                LOG.debug("Servicios disponibles: ");
                while (services.hasNext()) {
                    Service ser = services.next();
                    LOG.debug(ser);
                    LOG.debug("Algoritmo disponible: " + ser.getAlgorithm());
                }               
            }
        } catch (KeyStoreException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_1, ex.getMessage()), ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_1, ex.getMessage()), ex);
        } catch (CertificateException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_1, ex.getMessage()), ex);
        } catch (CardNotPresentException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_2, ex.getMessage()), ex);
        } catch (AuthenticationModeLockedException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_3, ex.getMessage()), ex);            
        } catch (InvalidCardException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_4, ex.getMessage()), ex);
        } catch (NoReadersFoundException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_5, ex.getMessage()), ex);
        } catch (IllegalStateException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_6, ex.getMessage()), ex);            
        } catch (CardException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);            
        } catch (ApduConnectionException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);            
        } catch (IOException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_1, ex.getMessage()), ex);
        }

	}
    /**
     * <p>Devuelve el Provider que permite trabajar con el KeyStore configurado.</p>
     * @param cert Certificado para el que se necesita acceso al provider
     * @return Provider asociado al KeyStore
     */
	public Provider getProvider(X509Certificate cert) {
		return Security.getProvider(DNI_PROVIDER);
	}
	
    /**
     * <p>Devuelve la cadena de certificación de un certificado.</p>
     * @param certificate certificado del que construir la cadena
     * @return Cadena de certificación
     * @throws CertStoreException Lanzado si hay algún problema en la construcción de la cadena
     * @see es.mityc.javasign.pkstore.keystore.KSStore#getCertPath(X509Certificate)
     */
    public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
        try {
            return (pkStore != null) ? pkStore.getCertPath(certificate) : null;
        } catch (AuthenticationModeLockedException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_3, ex.getMessage()), ex);
        } catch (ProviderException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);
        }
    }
    
    /**
     * <p>Devuelveun proxy a la clave privada asociada al certificado indicado.</p>
     * @param certificate certificado del que se consulta la clave privada
     * @return clave privada asociada al certificado
     * @throws CertStoreException Lanzado si hay algún problema al intentar recuperar la clave privada o no existe
     * @see es.mityc.javasign.pkstore.keystore.KSStore#getPrivateKey(X509Certificate)
     */
    public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
        try {
            return (pkStore != null) ? pkStore.getPrivateKey(certificate) : null;
        } catch (AuthenticationModeLockedException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_3, ex.getMessage()), ex);
        } catch (ProviderException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);
        }
    }
    
    /**
     * <p>Recupera los certificados que pueden firmar (disponen de clave privada) de este almacén.</p>
     * @return Listado de certificados que pueden firmar
     * @throws CertStoreException Lanzado si hay algún problema en la recuperación de certificados
     * @see es.mityc.javasign.pkstore.keystore.KSStore#getSignCertificates()
     */
    public List<X509Certificate> getSignCertificates() throws CertStoreException {
        try {
            return (pkStore != null) ? pkStore.getSignCertificates() : null;
        } catch (AuthenticationModeLockedException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_3, ex.getMessage()), ex);
        } catch (ProviderException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);
        }
    }
    
    /**
     * <p>Recupera los certificados de confianza de este almacén.</p>
     * @return Listado de certificados de confianza
     * @throws CertStoreException Lanzado si hay algún problema en la recuperación de certificados
     * @see es.mityc.javasign.pkstore.keystore.KSStore#getTrustCertificates()
     */
    public List<X509Certificate> getTrustCertificates() throws CertStoreException {
        try {
            return (pkStore != null) ? pkStore.getTrustCertificates() : null;
        } catch (AuthenticationModeLockedException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_3, ex.getMessage()), ex);
        } catch (ProviderException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);
        }
    }
    
    public List<X509Certificate> getPublicCertificates() throws CertStoreException {
        try {
            return (pkStore != null) ? pkStore.getPublicCertificates() : null;
        } catch (AuthenticationModeLockedException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_3, ex.getMessage()), ex);
        } catch (ProviderException ex) {
            throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_DNIE_7, ex.getMessage()), ex);
        }
    }

}