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
package es.mityc.javasign.pkstore.mozilla;

import java.util.MissingResourceException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * <p>Recupera la contraseña de acceso a un dispositivo de seguridad de Mozilla mostrando una ventana propia de diálogo.</p>
 * 
 */
public class PassStoreMozilla implements PasswordCallback, IPINDialogConfigurable {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(PassStoreMozilla.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Título de la ventana.*/
	private String title = null;
	/** Mensaje de tipo de contarseña esperada. */
	private String pinMessage = null;
	/** Modo de funcionamiento de los mensajes de la ventana. Por defecto automático. */
	private MESSAGES_MODE mode = MESSAGES_MODE.AUTO;
			
	/**
	 * <p>Vuelve a requerir la contraseña al usuario.</p>
	 * @param info tipo de requerimiento de contraseña que se está atendiendo
	 * @return contraseña recuperada
	 * @throws GiveUpException Lanzada si en los casos:
	 * 			<ul><li>existe algún problema a la hora de presentar la ventana</li>
	 * 			<li>el usuario cancela la introducción de contraseña</li></ul>
	 * @see org.mozilla.jss.util.PasswordCallback#getPasswordAgain(org.mozilla.jss.util.PasswordCallbackInfo)
	 */
	public Password getPasswordAgain(final PasswordCallbackInfo info) throws GiveUpException {
		try {
			PINDialog pinDialog = new PINDialog(null);
			switch (mode) {
				case AUTO_TOKEN:
					pinDialog.setTitle(info.getName());
					if (pinMessage != null) {
						pinDialog.setPINMessage(pinMessage);
					}
					break;
				case EXPLICIT:
					if (title != null) {
						pinDialog.setTitle(title);
					}
					if (pinMessage != null) {
						pinDialog.setPINMessage(pinMessage);
					}
					break;
				default:
			}
			pinDialog.pack();
			pinDialog.setVisible(true);

			if (pinDialog.isCancelado()) {
				throw new GiveUpException();
			}
			
			char[] pass = pinDialog.getPassword();
			pinDialog.dispose();
			return new Password(pass);
		} catch (MissingResourceException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_1), ex);
			throw new GiveUpException();
		}
	}

	/**
	 * <p>Pide la contraseña al usuario por primera vez.</p>
	 * @param info tipo de requerimiento de contraseña que se está atendiendo
	 * @return contraseña recuperada
	 * @throws GiveUpException Lanzada si en los casos:
	 * 			<ul><li>existe algún problema a la hora de presentar la ventana</li>
	 * 			<li>el usuario cancela la introducción de contraseña</li></ul>
	 * @see org.mozilla.jss.util.PasswordCallback#getPasswordFirstAttempt(org.mozilla.jss.util.PasswordCallbackInfo)
	 */
	public Password getPasswordFirstAttempt(final PasswordCallbackInfo info) throws GiveUpException {
		try {
			PINDialog pinDialog = new PINDialog(null);
			switch (mode) {
				case AUTO_TOKEN:
					pinDialog.setTitle(info.getName());
					if (pinMessage != null) {
						pinDialog.setPINMessage(pinMessage);
					}
					break;
				case EXPLICIT:
					if (title != null) {
						pinDialog.setTitle(title);
					}
					if (pinMessage != null) {
						pinDialog.setPINMessage(pinMessage);
					}
					break;
				default:
			}
			pinDialog.pack();
			pinDialog.setVisible(true);
			if (pinDialog.isCancelado()) { 
				throw new GiveUpException();
			}
			char[] pass = pinDialog.getPassword();
			pinDialog.dispose();
			return new Password(pass);
		} catch (MissingResourceException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_1), ex);
			throw new GiveUpException();
		}
	}
	
	/**
	 * <p>Establece el mensaje sobre el tipo de contraseña esperada.</p>
	 * 
	 * @param message Cadena con el tipo de contraseña esperada 
	 * @see es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable#setPINMessage(java.lang.String)
	 */
	public void setPINMessage(final String message) {
		pinMessage = new String(message);
	}
	
	/**
	 * <p>Establece el título que tendrá la ventana de petición de contraseña.</p>
	 * @param titleWindow título de la ventana
	 * @see es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable#setTitle(java.lang.String)
	 */
	public void setTitle(final String titleWindow) {
		this.title = new String(titleWindow);
	}
	
	/**
	 * Indica el modo en el que se deben obtener los mensajes de la ventana. Por defecto (o por ausencia de valor) actúa como AUTO.
	 * @param messagesMode	<ul><li>AUTO indica que el dialog buscará sus propios títulos</li> 
	 * 				<li>AUTO_TOKEN indica que utilizará los títulos que le proporcione el token</li>
	 * 				<li>EXPLICIT indica que utilizará los títulos que se le provea a través de los métodos de este interfaz</li></ul>
	 * @see es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable#setMessagesMode(es.mityc.javasign.pkstore.mozilla.IPINDialogConfigurable.MESSAGES_MODE)
	 */
	public void setMessagesMode(final MESSAGES_MODE messagesMode) {
		this.mode = messagesMode;
	}
}
