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

import java.security.cert.X509Certificate;

/**
 * <p>Interfaz para acceder a las contraseñas pedidas cuando se accede a la clave asociada a un certificado.</p>
 * 
 */
public interface IPassStoreKS {
	
	/**
	 * <p>Se llama a este método cuando el {@link IPKStoreManager} intenta acceder a la clave privada asociada a un certificado contenido
	 * en el KeyStore.</p>
	 * 
	 * @param certificate Certificado que tiene la clave
	 * @param alias Alias del certificado
	 * @return Se debe devolver la contraseña de acceso a la clave
	 */
	char[] getPassword(X509Certificate certificate, String alias); 

}
