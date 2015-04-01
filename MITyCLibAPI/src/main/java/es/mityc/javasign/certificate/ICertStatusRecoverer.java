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
package es.mityc.javasign.certificate;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>Interfaz que deben implementar los recuperadores de estado de los certificados.</p>
 * 
 */
public interface ICertStatusRecoverer {
	
	/**
	 * <p>Recupera el estado del certificado indicado.</p>
	 * 
	 * @param cert Certificado que se consulta
	 * @return Estado del certificado
	 * @throws CertStatusException Lanzada cuando no se puede recuperar el estado del certificado
	 */
	ICertStatus getCertStatus(X509Certificate cert) throws CertStatusException;
	
	/**
	 * <p>Recupera el estado de un conjunto de certificados.</p>
	 * 
	 * @param certs Certificados que se consultan
	 * @return Listado con el estado de cada uno de los certificados
	 * @throws CertStatusException Lanzada cuando no se puede recuperar el estado de algún certificado
	 */
	List<ICertStatus> getCertStatus(List<X509Certificate> certs) throws CertStatusException;

    /**
     * <p>
     * Recupera el estado de la cadena de certificación del certificado indicado.
     * </p>
     * 
     * @param cert
     *            Certificado que se consulta
     * @return Lista de estados de la cadena de certificación del certificado
     *         consultado. El primer elemento de la lista será el estado del
     *         propio certificado.
     * @throws CertStatusException
     *             Lanzada cuando no se puede recuperar el estado del
     *             certificado
     */
    List<ICertStatus> getCertChainStatus(X509Certificate cert) throws CertStatusException;

    /**
     * <p>
     * Recupera el estado de la cadena de certificación del conjunto de
     * certificados indicados.
     * </p>
     * 
     * @param certs
     *            Certificados que se consultan
     * @return Listado con la lista de estados de la cadena de certificación de
     *         cada uno de los certificados consultados. En cada lista el primer
     *         elemento será el estado del propio certificado consultado
     * @throws CertStatusException
     *             Lanzada cuando no se puede recuperar el estado de algún
     *             certificado
     */
    List<List<ICertStatus>> getCertChainStatus(List<X509Certificate> certs) throws CertStatusException;

}
