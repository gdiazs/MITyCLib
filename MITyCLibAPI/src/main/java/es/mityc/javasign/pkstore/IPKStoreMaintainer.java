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
package es.mityc.javasign.pkstore;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.swing.JPanel;

/**
 * <p>Interfaz para el mantenimiento de un almacén de certificados.</p>
 * <p>Mediante la implementación de este interfaz se obtiene acceso a la manipulación de los certificados disponibles en el almacén de certificados.</p>
 * 
 */
public interface IPKStoreMaintainer {

	/**
	 * <p>Inicializa el acceso al almacén.</p>
	 * 
	 * @throws CertStoreException lanzada si hay algún problema en el acceso al almacén
	 */
	void init() throws CertStoreException;

	/**
     * <p>Introduce un certificado de confianza en el almacén de certificados.</p>
     * 
     * @param cert Certificado de confianza
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
	void addTrustCert(X509Certificate cert) throws CertStoreException;

	/**
     * <p>Borra un certificado del almacén de certificados.</p>
     * <p>Si el certificado que se intenta eliminar no es un certificado de confianza, sino de firma, no se deberá eliminar.</p>
     * 
     * @param cert Certificado de confianza a eliminar 
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
	void removeTrustCert(X509Certificate cert) throws CertStoreException;
	
	/**
	 * <p>Importa un certificado de firma (incluye clave privada) en el almacén.</p>
	 * 
	 * @param pk Clave privada a importar
	 * @param cert Certificado asociado a la clave pública relacionada con la clave privada importada
	 * @param password Contraseña que se aplicará a la clave privada en el almacén
	 * @throws CertStoreException lanzada si hay algún problema en la importación de la clave privada y certificado
	 */
	void importSignCert(PrivateKey pk, X509Certificate cert, char[] password) throws CertStoreException;
	
	/**
	 * <p>Elimina un certificado del almacén de certificados que esté asociado a una clave privada, junto con la clave privada.</p>
	 * 
	 * @param cert Certificado asociado a una clave privada a eliminar
	 * @throws CertStoreException lanzada si hay algún problema en la eliminación del certificado y de la clave privada
	 */
	void removeSignCert(X509Certificate cert) throws CertStoreException;
	
	/**
	 * <p>Actualiza el certificado asociado a una clave privada, reemplazando el anterior asociado.</p>
	 *  
	 * @param cert certificado actual
	 * @throws CertStoreException lanzada si hay algún problema en la actualización del certificado
	 */
	void updateSignCert(X509Certificate cert) throws CertStoreException;
	
	/**
	 * <p>Indica si un certificado se puede borrar del almacén de certificados.</p>
	 * @param cert .- Certificado a consultar
	 * @return .- <code>true</code> si el certificado el borrable
	 */
	boolean isDeletable(X509Certificate cert);
	
	/**
	 * <p>Devuelve el panel de configuración propio de la implementación del almacén.</p>
	 * @return Panel de configuración del almacén.
	 */
	JPanel getPreferencesPanel();
}
