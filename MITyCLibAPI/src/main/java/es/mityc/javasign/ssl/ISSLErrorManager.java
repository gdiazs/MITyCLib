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
package es.mityc.javasign.ssl;

import java.security.cert.X509Certificate;

/**
 * <p>Interfaz para comunicar de errores encontrados en la verificación de la conexión SSL.</p>
 * 
 */
public interface ISSLErrorManager {
	
	/**
	 * <p>Indica que se ha producido un error al comprobar la identidad del servidor.</p>
	 * <p>El certificado del servidor y el nombre del host no coinciden.</p>
	 * @param actualHost Nombre resuelto del peer
	 * @param certServer Certificado obtenido del servidor
	 * @return <code>true</code> si se debe continuar, <code>false</code> si se debe parar el establecimiento del SSL
	 */
	boolean continueErrorPeer(String actualHost, X509Certificate certServer);

}
