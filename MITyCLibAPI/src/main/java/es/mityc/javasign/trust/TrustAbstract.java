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
import java.security.cert.X509Certificate;


/**
 * <p>Clase base para las clases encargadas de realizar labores de confianza.</p>
 * 
 */
public abstract class TrustAbstract {
	
	/**
	 * Devuelve una instancia del validador.
	 * 
	 * Este método tiene que ser sobreescrito por la clase que extienda el validador.
	 * 
	 * @return Instancia del validador
	 */
	public static TrustAbstract getInstance() {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * <p>Indica si el objeto indicado es catalogado como de confianza.</p>
	 * 
	 * @param data Objeto del que comprobar su confianza
	 * @throws TrustException lanzada cuando el objeto no es de confianza o ha ocurrido algún error al intentar comprobarlo:
	 * <ul>
	 * 	<li>{@link UnknownTrustException} lanzada cuando se desconoce si el objeto es o no de confianza (el objeto es desconocido o no
	 * 		se puede comprobar su confianza).</li>
	 * 	<li>{@link NotTrustedException} lanzada cuando el objeto no es de confianza.</li>
	 * </ul>
	 */
	public abstract void isTrusted(final Object data) throws TrustException;
	
	/**
	 * <p>Devuelve la cadena de certificados correspondiente al certificado parametrizado.</p>
	 * @param cert Certificado del cual se va a reconstruir su cadena
	 * @return Cadena de certificados correspondiente
	 * @throws UnknownTrustException Si no se dispone de la ruta de certificación
	 */
	public abstract CertPath getCertPath(X509Certificate cert) throws UnknownTrustException;

}
