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
package es.mityc.javasign.pkstore.pkcs11;

import java.security.cert.X509Certificate;

import es.mityc.javasign.pkstore.DefaultPassStoreKS;

/**
 * <p>Proporciona un mecanismo por defecto para mostrar una ventana que pida al usuario la contraseña de acceso a un certificado ubicado en un dispositivo seguro.</p>
 * 
 */
public class DefaultPassStoreP11 extends DefaultPassStoreKS {
	
	/**
	 * <p>Establece como título de la ventana de petición de certificado el alias provisto.</p>
	 * @param certificate certificado
	 * @param alias Alias del certificado
	 * @see es.mityc.javasign.pkstore.DefaultPassStoreKS#processData(java.security.cert.X509Certificate, java.lang.String)
	 */
	@Override
	protected void processData(final X509Certificate certificate, final String alias) {
		if (alias != null) {
			setPINMessage(alias);
		}
	}

}
