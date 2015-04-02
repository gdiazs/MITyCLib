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
package es.mityc.javasign.issues;

import java.security.cert.X509Certificate;

import es.mityc.javasign.pkstore.IPassStoreKS;

/**
 * <p>Permite automatizar el acceso a las contraseñas de los almacenes de certificados de testeo.</p>
 * 
 */
public class PassStoreKS implements IPassStoreKS {
	
	/** Contraseña de acceso al almacén. */
	private transient String password;
	
	/**
	 * <p>Crea una instancia con la contraseña que se utilizará con el almacén relacionado.</p>
	 * @param pass Contraseña del almacén
	 */
	public PassStoreKS(final String pass) {
		this.password = new String(pass);
	}

	/**
	 * <p>Devuelve la contraseña configurada para este almacén.</p>
	 * @param certificate No se utiliza
	 * @param alias no se utiliza
	 * @return contraseña configurada para este almacén
	 * @see es.mityc.javasign.pkstore.IPassStoreKS#getPassword(java.security.cert.X509Certificate, java.lang.String)
	 */
	public char[] getPassword(final X509Certificate certificate, final String alias) {
		return password.toCharArray();
	}

}
