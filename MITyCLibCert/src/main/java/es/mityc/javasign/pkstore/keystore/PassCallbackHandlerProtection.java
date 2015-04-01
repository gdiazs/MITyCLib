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
package es.mityc.javasign.pkstore.keystore;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPassStoreKS;

/**
 * <p>Wrapper necesario para KeyStore para la obtención de contraseñas según el interfaz {@link IPassStoreKS}.</p>
 */
public class PassCallbackHandlerProtection implements CallbackHandler {

	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Manejador de las contraseñas. */
	private IPassStoreKS passHandler;
	
	/**
	 * <p>Constructor.</p>
	 * @param passwordHandler manejador de las contraseñas 
	 */
	public PassCallbackHandlerProtection(IPassStoreKS passwordHandler) {
		this.passHandler = passwordHandler;
	}
	
	/**
	 * <p>Maneja las consultas de acceso a contraseñas.</p>
	 * @param callbacks Peticiones de contraseñas recibidas
	 * @throws IOException Lanzada si hay errores en el acceso a la contraseña
	 * @throws UnsupportedCallbackException Lanzada si el tipo de Callback recibido no se aplica
	 * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
	 */
	public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			if ((passHandler != null) &&
				(callbacks[i] instanceof PasswordCallback)) {
                 PasswordCallback pc = (PasswordCallback) callbacks[i];
                 pc.setPassword(passHandler.getPassword(null, pc.getPrompt()));
             } else {
                 throw new UnsupportedCallbackException(callbacks[i], I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_3));
             }
          }
	}
}
