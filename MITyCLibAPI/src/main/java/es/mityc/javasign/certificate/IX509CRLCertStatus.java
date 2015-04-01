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
package es.mityc.javasign.certificate;

import java.security.cert.X509CRL;

/**
 * <p>Interfaz que han de cumplir los objetos que recojan información de estado de un certificado en forma CRL.</p>
 * 
 */
public interface IX509CRLCertStatus extends ICertStatus {
	
	/**
	 * <p>Devuelve la CRL que contiene el estado del certificado en su forma X509CRL.</p>
	 * 
	 * @return X509CRL que contiene la CRL
	 */
	X509CRL getX509CRL();

}
