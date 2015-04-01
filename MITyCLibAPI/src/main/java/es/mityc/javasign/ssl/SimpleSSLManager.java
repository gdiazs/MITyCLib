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
 * <p>Gestión de la pasarela SSL de comunicación del cliente TS.</p>
 * 
 */
public class SimpleSSLManager implements ISSLManager {
	
	/** Gestionador de la confianza para el otro punto de conexión. */
	private TrustManager truster;
	/** Gestionador de las claves para la autenticación de este punto. */ 
	private KeyManager keyer;
	/** Gestionador de los errores del establecimiento de la sesión SSL. */
	private ISSLErrorManager errorManager;
	
	/**
	 * <p>Constructor.</p>
	 * @param trustManager gestionador de la confianza
	 * @param keyManager gestionador de la autenticación
	 */
	public SimpleSSLManager(TrustManager trustManager, KeyManager keyManager) {
		this.truster = trustManager;
		this.keyer = keyManager;
	}
	
	/**
	 * <p>Establece el gestionador de errores en las comunicaciones SSL.</p>
	 * @param errorMng Manager de errores
	 */
	public void setSSLErrorManager(final ISSLErrorManager errorMng) {
		this.errorManager = errorMng;
	}
	
	/**
	 * <p>Devuelve el manager de errores establecido.</p>
	 * @return manager de errores
	 * @see es.mityc.javasign.ssl.ISSLManager#getSSLErrorManager()
	 */
	public ISSLErrorManager getSSLErrorManager() {
		return errorManager;
	}
	
	/**
	 * <p>Devuelve el gestionador de autenticación de este punto.</p>
	 * @return gestionador de autenticación
	 * @see es.mityc.javasign.ssl.ISSLManager#getKeyManager()
	 */
	public KeyManager getKeyManager() {
		return keyer;
	}
	
	/**
	 * <p>Devuelve el gestionador de confianza del otro punto.</p>
	 * @return gestionador de confianza
	 * @see es.mityc.javasign.ssl.ISSLManager#getTrustManager()
	 */
	public TrustManager getTrustManager() {
		return truster;
	}

}
