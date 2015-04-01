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
/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.javasign.pkstore.mozilla;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

/**
 * <p>Recupera la contraseña de acceso a un dispositivo de seguridad de Mozilla de un fichero de propiedades de manera automática.</p>
 * <p>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testMozilla.properties</code>. El fichero
 * deber incluir la propiedad:
 * <pre>
 * # Contraseña al almacén de certificados utilizado en los tests
 * test.mozilla.password=
 * </pre>
 * </p>
 * 
 */
public class HandlerPassStoreMozilla implements PasswordCallback, IPINDialogConfigurable {
	
	/** Campo que recoge la contraseña de acceso al almacén de Mozilla. */
	private transient String pass = "";
	
	/**
	 * <p>Crea un gestionador de contraseña para el almacén de mozilla según la configuración.</p>
	 */
	public HandlerPassStoreMozilla() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testMozilla");
			pass = rb.getString("test.mozilla.password");
		} catch (MissingResourceException ex) {
		}
	}
	
	/**
	 * <p>Devuelve la contraseña configurada.</p>
	 * @param info No se utiliza
	 * @return contraseña configurada
	 * @throws GiveUpException Nunca se lanza
	 * @see org.mozilla.jss.util.PasswordCallback#getPasswordAgain(org.mozilla.jss.util.PasswordCallbackInfo)
	 */
	public Password getPasswordAgain(final PasswordCallbackInfo info) throws GiveUpException {
		return new Password(pass.toCharArray());
	}

	/**
	 * <p>Devuelve la contraseña configurada.</p>
	 * @param info No se utiliza
	 * @return contraseña configurada
	 * @throws GiveUpException Nunca se lanza
	 * @see org.mozilla.jss.util.PasswordCallback#getPasswordFirstAttempt(org.mozilla.jss.util.PasswordCallbackInfo)
	 */
	public Password getPasswordFirstAttempt(final PasswordCallbackInfo info) throws GiveUpException {
		return new Password(pass.toCharArray());
	}

	/**
	 * <p>No se utiliza.</p>
	 * @param message no se utiliza
	 * @see es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable#setPINMessage(java.lang.String)
	 */
	public void setPINMessage(final String message) {
	}
	
	/**
	 * <p>No se utiliza.</p>
	 * @param title no se utiliza
	 * @see es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable#setTitle(java.lang.String)
	 */
	public void setTitle(final String title) {
	}
	
	/**
	 * <p>No se utiliza.</p>
	 * @param mode no se utiliza
	 * @see es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable#setMessagesMode(es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable.MESSAGES_MODE)
	 */
	public void setMessagesMode(final MESSAGES_MODE mode) {
	}

}
