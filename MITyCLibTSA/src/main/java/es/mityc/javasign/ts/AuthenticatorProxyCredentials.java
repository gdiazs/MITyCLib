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
package es.mityc.javasign.ts;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Authenticator.RequestorType;

import org.apache.commons.httpclient.NTCredentials;

/**
 * <p>Credenciales de autenticación para conectar el sistema de autenticación de Java con el sistema de credenciales de la librería
 * httpclient.</p>
 *
 */
public class AuthenticatorProxyCredentials extends NTCredentials {
	
	protected PasswordAuthentication pa = null;

	public AuthenticatorProxyCredentials(String host, String domain) {
		super("username", "password", host, domain);
	}
	
	private void refreshAuthenticator() {
        String proxyHost = System.getProperty("http.proxyHost");
    	int proxyPort = 80;
    	try {
    		proxyPort = Integer.parseInt(System.getProperty("http.proxyPort"));
    	} catch (NumberFormatException ex) {
    	}
    	try {
    		pa = Authenticator.requestPasswordAuthentication(proxyHost, null, proxyPort, "HTTP", "", "http", null, RequestorType.PROXY);
    	} catch (SecurityException ex) {
    		pa = null;
    	}
	}
	
	@Override
	public String getUserName() {
		refreshAuthenticator();
    	if (pa == null)
    		return super.getUserName();
		return pa.getUserName();
	}
	
	@Override
	public String getPassword() {
		if (pa == null)
			refreshAuthenticator();
		if (pa == null)
			return super.getPassword();
		return new String(pa.getPassword());
	}

}
