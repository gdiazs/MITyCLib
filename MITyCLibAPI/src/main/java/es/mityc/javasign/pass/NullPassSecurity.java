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
package es.mityc.javasign.pass;

import java.util.Properties;

/**
 * <p>Gestor de seguridad que no ofusca las contraseñas.</p>
 */
public class NullPassSecurity implements IPassSecurity {
	/**
	 * <p>Constructor.</p>
	 */
	public NullPassSecurity() {
	}
	
	/**
	 * <p>Constructor.</p>
	 * @param config Configuración
	 */
	public NullPassSecurity(Properties config) {
	}

	/**
	 * <p>Protege la contraseña.</p>
	 * <p>En esta implementación se devuelve la misma información que la provista.</p>
	 * @param pass datos a proteger
	 * @return misma <i>pass</i> provista
	 * @throws PassSecurityException Nunca se lanza
	 * @see es.mityc.javasign.pass.IPassSecurity#protect(java.lang.String)
	 */
	public String protect(final String pass) throws PassSecurityException {
		return (pass != null) ? new String(pass) : null;
	}

	/**
	 * <p>Recupera la contraseña indicada.</p>
	 * <p>En esta implementación se devuelve la misma información que la provista.</p>
	 * @param pass datos protegidos
	 * @return misma <i>pass</i> provista
	 * @throws PassSecurityException Nunca se lanza
	 * @see es.mityc.javasign.pass.IPassSecurity#recover(java.lang.String)
	 */
	public String recover(final String pass) throws PassSecurityException {
		return (pass != null) ? new String(pass) : null;
	}

}
