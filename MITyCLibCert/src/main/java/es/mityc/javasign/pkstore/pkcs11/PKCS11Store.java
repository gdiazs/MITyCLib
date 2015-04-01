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
package es.mityc.javasign.pkstore.pkcs11;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.List;

import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;

/**
 * Wrapper para permitir utilizar los servicios de un dispositivo PKCS#11 (acceso a los servicios criptográficos de un dispositivo externo).
 *  
 */
public class PKCS11Store implements IPKStoreManager {
	
	/**
	 * <p>Crea una instancia relacionándola con un dispositivo PKCS#11.</p>
	 * 
	 * @param libpath Ruta donde se encuentra la librería de sistema PKCS#11 que da acceso al dispositivo
	 * @param passHandler Manejador que servirá para recuperar las claves del dispositivo
	 */
	public PKCS11Store(final String libpath, IPassStoreKS passHandler) {
		// TODO: establece la ruta de la librería nativa de acceso al dispositivo PKCS#11. Instancia un provider SunPKCS11 adecuado
	}
	
	/**
	 * <p>Obtiene la cadena de certificados asociada al certificado indicado.</p>
	 * 
	 * No implementado
	 * 
	 * @param certificate Certificado base de la cadena
	 * @return No implementado
	 * @throws CertStoreException Lanzada cuando hay problemas en la construcción de la cadena de certificados según los certificados del dispositivo PKCS#11
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Obtiene un wrapper de acceso a la clave privada asociada al certificado indicado.</p>
	 * 
	 * @param certificate Certificado del que se requiere la clave privada
	 * @return Clave privada asociada al certificado
	 * @throws CertStoreException Lanzada cuando hay problemas en el acceso a una clave privada del dispositivo PKCS#11
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		// TODO: accede al Keystore del provider asociado al dispositivo y pide la clave asociada al certificado (buscando por alias).
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Se devuelve el provider que da acceso a las capacidades criptográficas del dispositivo relacionado.</p>
     * @param certificate Certificado para el que se necesita acceso al provider
	 * @return provider asociado al dispositivo
	 */
	public Provider getProvider(final X509Certificate certificate) {
		// TODO: devolver el provider asociado al dispositivo
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Devuelve los certificados que tienen asociado clave privada.</p>
	 * 
	 * @return Lista con los certificados que tienen clave privada
	 * @throws CertStoreException Lanzada cuando no se tiene acceso a los certificados de firma
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		// TODO: accede al KeyStore del provider asociado al dispositivo y pide los elementos que son PrivateKeyEntry
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Devuelve los certificados de confianza disponibles en el dispositivo externo.</p>
	 * 
	 * @return certificados de confianza disponibles en el dispositivo 
	 * @throws CertStoreException Lanzada cuando no se tiene acceso a certificados de confianza del dispositivo
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		// TODO: accede al KeyStore del provider asociado al dispositivo y pide los elementos que son TrustedCertificateEntry
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		// TODO: accede al KeyStore del provider asociado al dispositivo y pide los elementos que son TrustedCertificateEntry
		throw new UnsupportedOperationException("Not implemented yet");
	}

}
