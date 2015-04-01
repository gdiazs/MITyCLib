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
package es.mityc.javasign.pkstore.keystore;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.List;

import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;

/**
 * <p>Wrapper para permitir utilizar KeyStores en los componentes de firma.</p>
 * 
 */
public class KSStore implements IPKStoreManager {
	/** KeyStore de java/sun al que se conecta este wrapper. */
	private KeyStore ks;
	/** Gestionador de las contraseñas de acceso al keystore. */
	private IPassStoreKS passHandler;
	/** Proveedor necesario para el acceso al keystore. */
	private Provider provider;
	/** Cadena equivalente a password nulo. */
	private char[] nullPassword = KeyTool.EMPTY_STRING;
	
	/**
	 * <p>Constructor.</p>
	 * 
	 * @param keystore Keystore ya inicializado
	 * @param passwordHandler Manejador que servirá para recuperar las claves del KeyStore
	 */
	public KSStore(KeyStore keystore, IPassStoreKS passwordHandler) {
		this.ks = keystore;
		this.passHandler = passwordHandler;
		this.provider = keystore.getProvider();
	}

	/**
	 * <p>Constructor.</p>
	 * 
	 * @param keystore Keystore ya inicializado
	 * @param passwordHandler Manejador que servirá para recuperar las claves del KeyStore
	 * @param nullpass cadena de contraseña nula
	 */
	public KSStore(KeyStore keystore, IPassStoreKS passwordHandler, char[] nullpass) {
		this.ks = keystore;
		this.passHandler = passwordHandler;
		this.provider = keystore.getProvider();
		this.nullPassword = nullpass;
	}

	/**
	 * <p>Constructor.</p>
	 * @param keystore Keystore inicializado
	 * @param specificProvider especifica un provider distinto del de Keystore
	 * @param passwordHandler Manejador que servirá para recuperar las claves del KeyStore
	 */
	public KSStore(KeyStore keystore, Provider specificProvider, IPassStoreKS passwordHandler) {
		this.ks = keystore;
		this.passHandler = passwordHandler;
		this.provider = specificProvider;
	}
	
	/**
	 * <p>Constructor.</p>
	 * @param keystore Keystore inicializado
	 * @param specificProvider especifica un provider distinto del de Keystore
	 * @param passwordHandler Manejador que servirá para recuperar las claves del KeyStore
	 * @param nullpass cadena de contraseña nula
	 */
	public KSStore(KeyStore keystore, Provider specificProvider, IPassStoreKS passwordHandler, char[] nullpass) {
		this.ks = keystore;
		this.passHandler = passwordHandler;
		this.provider = specificProvider;
		this.nullPassword = nullpass;
	}

	/**
	 * Obtiene la cadena de certificados asociada a un certificado específico.
	 * 
	 * No implementado
	 * 
	 * @param certificate certificado base de la cadena de certificados
	 * @return Cadena de certificados relacionada con el certificado indicado
	 * @throws CertStoreException Lanzada cuando no haay problemas de acceso a los certificados del almacén
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * Obtiene acceso a la clave privada de un certificado específico.
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
		return KeyTool.findPrivateKey(ks, certificate, passHandler, nullPassword);
	}

	/**
	 * <p>Devuelve el Provider que permite trabajar con el KeyStore configurado.</p>
     * @param cert Certificado para el que se necesita acceso al provider
	 * @return Provider asociado al KeyStore
	 */
	public Provider getProvider(final X509Certificate cert) {
		return provider;
	}

	/**
	 * <p>Recupera los certificados que pueden firmar contenidos en el KeyStore.</p>
	 * 
	 * @return Listado de certificados con clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con el KeyStore interno
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		return KeyTool.getCertificatesWithKeys(ks);
	}

	/**
	 * <p>Recupera los certificados de confianza contenidos en el KeyStore.</p>
	 * 
	 * @return Listado de certificados de confianza
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con el KeyStore interno
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		return KeyTool.getTrustCertificates(ks);
	}
	
	
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		return KeyTool.getCertificatesWithoutKeys(ks);
	}
}
