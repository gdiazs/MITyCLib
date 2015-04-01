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
package es.mityc.javasign.pkstore.mitycstore.PKHandlers;

import java.security.cert.X509Certificate;

import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.DefaultPassStoreKS;
import es.mityc.javasign.pkstore.mitycstore.CertUtil;
import es.mityc.javasign.pkstore.mitycstore.mantainer.DialogoCert;

/**
 * <p>Muestra un diálogo de confirmación para borrar un certificado del almacén.</p>
 * 
 */
public class DeleteWarnHandler extends DefaultPassStoreKS {

	/** Logger. */
	Log logger = LogFactory.getLog(DialogoCert.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/**
	 * <p>Método invocado al tratar de acceder a la clave privada del certificado. 
	 * Muestra el diálogo de confirmación.</p>
	 * @param certificate Certificado que será borrado del almacén
	 * @param alias Alias del certificado a borrar
	 * @return <code>null</code> Si se canceló, <code>char[0]</code> si se aceptó
	 */
	@Override
	public char[] getPassword(final X509Certificate certificate, final String alias) {
		String certCN = CertUtil.extractName(certificate.getSubjectX500Principal());
		// Opciones "Cancelar" y "Aceptar" 
		Object[] options = new Object[]{
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_CANCEL),
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_ACCEPT)};
		
		JOptionPane confirmDialog = new JOptionPane(
				// Se va a borrar el certificado llamado {0}\n¿Desea continuar?
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_83, certCN), // Mensaje a mostrar
				JOptionPane.QUESTION_MESSAGE,	// Es un mensaje de confirmación
				JOptionPane.NO_OPTION,			// No se muestra ninguna opción, salvo las indicadas en "options"
				null,							// Se establece el icono por defecto de los QUESTION_MESSAGE
				options,						// Colección de opciones
				options[0]); 					// Opción por defecto "Cancelar"
		
		// Título: "Acceso a clave privada"
		JDialog dialog = confirmDialog.createDialog(null, I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_5));
		// Se muestra el mensaje y se espera a que el usuario decida
        dialog.setVisible(true);
        dialog.dispose();

        // Se obtiene la opción seleccionada
        Object selectedValue = confirmDialog.getValue();
        String res = null;
        if (selectedValue != null && selectedValue instanceof String) {
        	res = String.valueOf(selectedValue);
        }

		if (res != null && options[1].equals(res)) {
			return new char[0];
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("Acceso a clave privada cancelado por el usuario");
			}
			return null;
		}
	}
}
