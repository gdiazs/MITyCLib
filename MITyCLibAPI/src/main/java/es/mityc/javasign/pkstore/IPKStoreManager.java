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
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>Interfaz para la manipulación de claves públicas/privadas y certificados en un ambiente de firma digital.</p>
 * 
 */

public interface IPKStoreManager {
    
    /**
     * <p>Provider que permite el acceso a funciones criptográficas relacionadas con los certificados (PK) disponibles
     * en el almacén.</p>
     * @param cert Certificado para el que se necesita acceso al provider
     * @return Provider que define sus servicios
     */
	Provider getProvider(X509Certificate cert);

    /**
     * <p>Obtiene un listado de los certificados del almacén que pueden realizar labores de firma.</p>
     * 
     * @return los certificados como un listado de X509Certificate
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
    List<X509Certificate> getSignCertificates() throws CertStoreException;
    
    /**
     * <p>Obtiene un listado de los certificados de las entidades de confianza disponibles en el almacén.</p>
     * 
     * @return los certificados como un listado de X509Certificate
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
    List<X509Certificate> getTrustCertificates() throws CertStoreException;
    
    /**
     * <p>Obtiene la cadena de certificados asociada al certificado indicado.</p>
     * 
     * @param certificate Certificado del que se quiere la cadena
     * @return CertPath construido con los certificados del almacén
     * @throws CertStoreException si hay algún problema en el acceso al almacén de certificados o el almacén no contiene el certificado
     * 		indicado
     */
    CertPath getCertPath(X509Certificate certificate) throws CertStoreException;
    
    /**
     * <p>Devuelve la clave privada que tiene el almacén asociado al certificado indicado.</p>
     * 
     * @param certificate Certificado del que se quiere la clave privada
     * @return PrivateKey relacionada con el certificado (puede ser una clase proxy)
     * @throws CertStoreException si hay algún problema en el acceso al almacén de certificados o no hay clave privada asociada
     */
    PrivateKey getPrivateKey(X509Certificate certificate) throws CertStoreException;
    
    /**
     * <p>Obtiene un listado de los certificados públicos disponibles en el almacén.</p>
     * 
     * @return los certificados como un listado de X509Certificate
     * @throws CertStoreException si hay algún problema en el acceso al almacén
     */
    List<X509Certificate> getPublicCertificates() throws CertStoreException;
}
