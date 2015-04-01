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

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.DefaultPassStoreKS;
import es.mityc.javasign.pkstore.mitycstore.CertUtil;

/**
 * <p>Pide la contraseña de acceso, y después la cachea para futuros accesos.</p>
 * 
 */
public class CachedPassHandler extends DefaultPassStoreKS {
	
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Mensage a mostrar en el diálogo. */
	private String pinMessage = I18N.getLocalMessage(ConstantsCert.I18N_CERT_SMR_CARD_PIN); // Introduzca la contraseña para
	
	/** Variable no serializable para almacenar la contraseña escrita. */
	private transient char[] pass = null;
	
	/**
	 * <p>Cachea la contraseña la primera vez.</p>
	 * <p>Si ambos argumentos son nulos, se configura el diálogo 
	 * para que sea usado para establecer una contraseña nueva 
	 * (Con un mensaje concreto y sin botón de cancelar).</p>
	 * 
	 * @param certificate Certificado al que se accede
	 * @param alias Alias del certificado al que se accede
	 * 
	 * @return contraseña (PIN)
	 */
	@Override
	public char[] getPassword(final X509Certificate certificate, final String alias) {
		if (pass == null) {
			pass = super.getPassword(certificate, alias);
		}
		
		return pass;
	}
	
	/**
	 * <p>Establece como título de la ventana de petición de certificado el alias provisto, o el nombre del certificado.</p>
	 * @param certificate certificado
	 * @param alias Alias del certificado
	 * @see es.mityc.javasign.pkstore.DefaultPassStoreKS#processData(java.security.cert.X509Certificate, java.lang.String)
	 */
	@Override
	protected void processData(final X509Certificate certificate, final String alias) {
		if (certificate == null && alias == null) {
			// Introduzca la nueva contraseña de acceso\n(Deje el campo vacío para que no se pida contraseña al acceder)
			setPINMessage(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_86));
			setCancelBtnVisible(false);
		} else if (alias != null) {
			setPINMessage(pinMessage + " " + alias);
		} else {
			setPINMessage(pinMessage + " " + CertUtil.extractName(certificate.getSubjectX500Principal()));
		}
	}
	
	/**
	 * <p>Resetea la contraseña para que se vuelva a pedir.</p>
	 */
	public void reset() {
		pass = null;
	}
}
