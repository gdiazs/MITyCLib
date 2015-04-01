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
package es.mityc.javasign.trust;

import java.security.cert.CertPath;

/**
 * <p>Interfaz que ha de implementar un validador de confianza de Certificados.</p>
 * 
 */
public interface ITrustSignCerts {
	
	/**
	 * <p>Comprueba si el path de certificados indicado pertenece a una entidad de confianza.</p>
	 *  
	 * @param certs Path de certificados
	 * @throws TrustException lanzada cuando el objeto no es de confianza o ha ocurrido algún error al intentar comprobarlo:
	 * <ul>
	 * 	<li>{@link UnknownTrustException} lanzada cuando se desconoce si el objeto es o no de confianza (el objeto es desconocido o no
	 * 		se puede comprobar su confianza).</li>
	 * 	<li>{@link NotTrustedException} lanzada cuando el objeto no es de confianza.</li>
	 * </ul>
	 */
	void isTrusted(CertPath certs) throws TrustException;
	
}
