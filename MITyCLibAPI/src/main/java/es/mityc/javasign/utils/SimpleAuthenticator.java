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
package es.mityc.javasign.utils;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 * <p>Authenticator que devuelve el usuario y contraseña configurados en cualquier circunstancia.</p>
 *
 */
public class SimpleAuthenticator extends Authenticator {
	
	/** Nombre del usuario. */
	private transient String username;
	/** Contraseña del usuario. */
	private transient String password; 

	/**
	 * <p>Constructor.</p>
	 * @param user Nombre del usuario
	 * @param pass contraseña del usuario
	 */
	public SimpleAuthenticator(final String user, final String pass) {
		super();
		this.username = (user != null) ? new String(user) : null;
		this.password = (pass != null) ? new String(pass) : null;
	}
	
	/**
	 * <p>Devuelve las credenciales configuradas.</p>
	 * @return Credenciales configuradas
	 * @see java.net.Authenticator#getPasswordAuthentication()
	 */
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return new PasswordAuthentication(username, (password != null) ? password.toCharArray() : null);
	}

}
