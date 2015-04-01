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
 * <p>Establece que la contraseña es un campo vacío, y avisa al usuario.</p>
 * 
 */
public class WarnPassHandler extends DefaultPassStoreKS {

	/** Logger. */
	Log LOG = LogFactory.getLog(DialogoCert.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	@Override
	public char[] getPassword(final X509Certificate certificate, final String alias) {
		String certCN = CertUtil.extractName(certificate.getSubjectX500Principal());
		// Se va a utilizar la clave privada asociada al certificado llamado {0}\n¿Desea continuar?
		// Acceso a clave privada
		int res = JOptionPane.showConfirmDialog(null, 
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_4, certCN),
				I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_5),
				JOptionPane.OK_CANCEL_OPTION);
		if (res == JOptionPane.CANCEL_OPTION) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Acceso a clave privada cancelado por el usuario");
			}
			return null;
		} else {
			return new char[0];
		}
	}
}
