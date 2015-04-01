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

import javax.swing.ImageIcon;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.DefaultPassStoreKS;
import es.mityc.javasign.pkstore.mitycstore.CertUtil;

/**
 * <p>Recupera la contraseña de acceso a un dispositivo de seguridad mostrando una ventana propia de diálogo.</p>
 * 
 */
public class Pkcs11PassHandler extends DefaultPassStoreKS {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Mensage a mostrar en el diálogo. */
	private String pinMessage = I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_PIN); // Introduzca la contraseña para
	
	/** Icono SIM del díalogo. */
	private static final ImageIcon PIN_ICON = new ImageIcon(Pkcs11PassHandler.class.getResource("/es/mityc/javasign/pkstore/mitycstore/Images/SIM.png"));
	
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
		} else {
			setPINMessage(pinMessage + " " + CertUtil.extractName(certificate.getSubjectX500Principal()));
		}
		
		setIcon(PIN_ICON);
	}
}
