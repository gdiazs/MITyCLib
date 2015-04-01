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

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

/**
 * <p>Interfaz que han de cumplir los gestionadores de las conexiones SSL del cliente.</p>
 * 
 */
public interface ISSLManager {
	
	/**
	 * <p>Devuelve el gestionador de confianza del otro peer de la conexión.</p>
	 * @return gestor de confianza
	 */
	TrustManager getTrustManager();
	
	/**
	 * <p>Devuelve el gestionador de la autenticación por parte de este peer de la conexión.</p>
	 * @return gestionador de las claves
	 */
	KeyManager getKeyManager();
	
	/**
	 * <p>Devuelve el gestionador ante errores en el establecimiento del SSL.</p>
	 * @return gestionador de errores, <code>null</code> si no se desea ninguno
	 */
	ISSLErrorManager getSSLErrorManager();

}
