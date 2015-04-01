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
package es.mityc.javasign.pkstore.iexplorer;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
import es.mityc.javasign.utils.CopyFilesTool;

/**
 * <p>Facade de acceso a los servicios del almacén de certificados de Internet Explorer mediante una implementación nativa propia.</p>
 * 
 */
public class IExplorerStore implements IPKStoreManager {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(IExplorerStore.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Clase nativa que conecta con el almacén de certificados de Microsoft. */
	private static IECSPJNI cspBridge = null;
    
    /**
     * <p>Constructor.</p>
     */
	public IExplorerStore() {
    	loadLibrary();
    }
    
    /**
     * <p>Copia la librería externa DLL al directorio temporal.</p>
     * @throws CopyFileException lanzada cuando no se puede copiar la librería nativa
     */
    private void copyLibrary() throws CopyFileException {
		CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_IE_PROPERTIES, this.getClass().getClassLoader());
		cft.copyFilesOS(null, ConstantsCert.CP_EXPLORER, true);
	}
    
    /**
     * <p>Carga la librería externa DLL encargada de realizar el puente con CSP.</p>
     */
    private synchronized void loadLibrary() {
        try {
            if (cspBridge == null) {
            	copyLibrary();
                cspBridge = new IECSPJNI();
            }
        } catch (Exception ex) {
        	LOG.fatal(I18N.getLocalMessage(ConstantsCert.I18N_CERT_IE_1, ex.getMessage()));
        	if (LOG.isDebugEnabled()) {
        		LOG.error("", ex);
        	}
        }
    }

	/**
	 * <p>Obtiene la cadena de certificación del certificado indicado.</p>
	 * <p>No implementado.</p>
	 * @param certificate Certificado del que se pide su cadena de certificación
	 * @return Cadena de certificación relacionada
	 * @throws CertStoreException no usado
	 * 
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getCertPath(java.security.cert.X509Certificate)
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Devuelve la clave privada disponible en el almacén asociada con el certificado.</p>
	 * @param certificate certificado del que se quiere la clave privada
	 * @return clave privada relacionada con el certificado
	 * @throws CertStoreException lanzada cuando hay problemas de acceso al almacén
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getPrivateKey(java.security.cert.X509Certificate)
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		return new PKProxyIE(certificate);
	}

	/**
	 * <p>Devuelve el provider que gestiona las capacidades critográficas que se pueden realizar con este almacén.</p>
     * @param cert Certificado para el que se necesita acceso al provider
	 * @return el proveedor {@link MITyCMSProvider}
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getProvider(X509Certificate)
	 * @see es.mityc.javasign.pkstore.iexplorer.MITyCMSProvider
	 */
	public Provider getProvider(final X509Certificate cert) {
		return new MITyCMSProvider();
	}

	/**
	 * <p>Devuelve los certificados de firma disponibles en el almacén.</p>
	 * @return listado con los certificados disponibles en el almacén personal
	 * @throws CertStoreException Lanzada cuando hay algún problema en el acceso al almacén
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getSignCertificates()
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
        ArrayList<X509Certificate> allCerts = new ArrayList<X509Certificate>();
		if (cspBridge != null) {
	        byte[][] bCertificados = cspBridge.getCertificatesInSystemStore(ConstantsCert.MY_STORE);
	        for (int i = 0; i < bCertificados.length; i++) {
	            byte [] bc = bCertificados[i];
	            
	            //Seleccionar el que coincida con el formato X509Certificate
	            CertificateFactory cfTemporal;
	            try {
	                cfTemporal = CertificateFactory.getInstance("X.509");
	                X509Certificate certX509Temporal =
	                        (X509Certificate) cfTemporal.generateCertificate(
	                        new ByteArrayInputStream(bc));
	                allCerts.add(certX509Temporal);
	            } 
	            catch (CertificateException ex) {
	                LOG.error(ex.getMessage(), ex);
	            }    
	        }
		}
        return allCerts;
	}

	/**
	 * <p>Devuelve los certificados de confianza disponibles en el almacén.</p>
	 * <p>No implementado.</p>
	 * @return listado con los certificados disponibles en el almacén de confianza
	 * @throws CertStoreException Lanzada cuando hay problemas de acceso al almacén
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getTrustCertificates()
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {		
		// TODO 
		throw new UnsupportedOperationException("Not implemented yet");
	}
	
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		// TODO
		throw new UnsupportedOperationException("Not implemented yet");
	}
}
