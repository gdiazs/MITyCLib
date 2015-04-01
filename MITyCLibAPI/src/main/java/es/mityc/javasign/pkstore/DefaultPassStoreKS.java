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
package es.mityc.javasign.pkstore;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.security.cert.X509Certificate;

import javax.swing.ImageIcon;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Proporciona un mecanismo por defecto para mostrar una ventana que pida al usuario la contraseña de acceso a un certificado ubicado en un dispositivo seguro.</p>
 * 
 */
public class DefaultPassStoreKS implements IPassStoreKS {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME);

	/** Título de la ventana de petición de contraseña. */
	private String titleDialog = I18N.getLocalMessage(ConstantsAPI.I18N_CERT_SMR_CARD_TITLE);

	/** Título de la ventana de petición de contraseña. */
	private String pinMessage = I18N.getLocalMessage(ConstantsAPI.I18N_CERT_SMR_CARD_PIN);
	
	/** Instancia de la ventana de diálogo para la petición de contraseña. */
	private PINDialog pinDialog = null;

	/**
	 * <p>Muestra una ventana de diálogo para que el usuario introduzca una contraseña de acceso a un certificado ubicado en un dispositivo seguro.</p>
	 * 
	 * @param certificate Certificado al que se accede
	 * @param alias Alias del certificado al que se accede
	 * @return contraseña (PIN)
	 */
	public char[] getPassword(final X509Certificate certificate, final String alias) {
		pinDialog = new PINDialog(null);
		processData(certificate, alias);
		pinDialog.setTitle(getTitle());
		pinDialog.setPINMessage(getPINMessage());
		pinDialog.pack();
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		pinDialog.setLocation(screenSize.width / 2 - pinDialog.getWidth() / 2, screenSize.height / 2 - pinDialog.getHeight() / 2);
		pinDialog.setVisible(true);

		char[] pass = new char[0];
		if (!pinDialog.isCancelado()) { 
			pass = pinDialog.getPassword();
		} 			
		pinDialog.dispose();
		
		return pass;
	}

	/**
	 * <p>Establece el icono que será mostrado junto con el mensaje de petición de PIN.</p>
	 * <p>Este método se mantiene para facilitar la gestión de hijos sobre la información a mostrar. 
	 * Sobreescribiéndolo se puede preparar un diálogo adecuado al caso.</p> 
	 * @param icon Icono a mostrar.
	 */
	public void setIcon(final ImageIcon icon) {
		pinDialog.setIcon(icon);
	}
	
	/**
	 * <p>Establece el icono que será mostrado junto con el mensaje de petición de PIN.</p>
	 * @param isVisible <code>false</code> para hacer el botón invisible
	 */
	public void setCancelBtnVisible(final boolean isVisible) {
		pinDialog.setCancelBtnVisible(isVisible);
	}
	
	/**
	 * <p>Procesa la información sobre el certificado del que se pide el acceso.</p>
	 * <p>Este método se mantiene para facilitar la gestión de hijos sobre la información a mostrar. Sobreescribiéndolo se puede preparar un título de ventana
	 * relacionado con los datos provistos.</p>
	 * @param certificate certificado del que se pide el acceso
	 * @param alias Alias del certificado
	 */
	protected void processData(final X509Certificate certificate, final String alias) {
		
	}
	
	/**
	 * <p>Permite indicar un título a la ventana de petición de contraseña.</p>
	 * @param title Título de la ventana
	 */
	public void setTitle(final String title) {
		this.titleDialog = new String(title);
	}
	
	/**
	 * <p>Devuelve el título configurado para la ventana de petición de contraseña.</p>
	 * @return Título de la ventana
	 */
	public String getTitle() {
		return titleDialog;
	}
	
	/**
	 * <p>Establece el mensaje de introducción de PIN.</p> 
	 * @param message nuevo mensage
	 */
	public void setPINMessage(final String message) {
		this.pinMessage = new String(message);
	}
	
	/**
	 * <p>Devuelve el mensaje de PIN introducido.</p>
	 * @return mensaje de PIN
	 */
	public String getPINMessage() {
		return pinMessage;
	}

}
