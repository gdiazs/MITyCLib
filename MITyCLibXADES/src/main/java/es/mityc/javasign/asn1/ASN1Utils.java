/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
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
package es.mityc.javasign.asn1;

import java.io.IOException;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.X509Name;

import es.mityc.javasign.ConstantsXAdES;
import es.mityc.javasign.certificate.OCSPResponderID;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Conjunto de utilidades para el tratamiento de campos ASN.1.</p>
 */
public class ASN1Utils {
	
	/** Logger. */
	private static Log LOG = LogFactory.getLog(ASN1Utils.class);
	/** Internacionalizador. */
	private static II18nManager I18N = I18nFactory.getI18nManager(ConstantsXAdES.LIB_NAME);
	
	/**
	 * <p>Constructor vacío.</p> 
	 */
	private ASN1Utils() {
	}
	
	/**
	 * <p>Obtiene la información sobre la identidad de un responder de OCSP mediante una estructura ASN.1.</p>
	 * @param responder Bloque ASN.1 que contiene la información del responder
	 * @return objeto con los datos del responder, <code>null</code> si no se ha podido formar
	 */
	public static OCSPResponderID getResponderID(ResponderID responder) {
		OCSPResponderID result = null;
        ASN1TaggedObject tagged = (ASN1TaggedObject) responder.toASN1Object();
		switch (tagged.getTagNo()) {
			case 1:
				try {
					X509Name name = X509Name.getInstance(tagged.getObject());
					result = OCSPResponderID.getOCSPResponderID(new X500Principal(name.getEncoded()));
				} catch (IllegalArgumentException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsXAdES.I18N_UTILS_1, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
				} catch (IOException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsXAdES.I18N_UTILS_1, ex.getMessage()));
					if (LOG.isDebugEnabled()) {
						LOG.debug("", ex);
					}
				}
				break;
			case 2:
				ASN1OctetString octect = (ASN1OctetString)tagged.getObject();
				result = OCSPResponderID.getOCSPResponderID(octect.getOctets());
				break;
		}
		return result;
	}

}
