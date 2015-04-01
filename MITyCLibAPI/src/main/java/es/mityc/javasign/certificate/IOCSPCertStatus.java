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

import java.util.Date;

/**
 * <p>Interfaz que han de cumplir los objetos que recojan información de estado de un certificado en forma OCSP.</p>
 * 
 */
public interface IOCSPCertStatus extends ICertStatus {
	
	/** Posibles tipos de identificación del OCSP Responder. */
	enum TYPE_RESPONDER {
		/** Por nombre: la cadena que identifica al OCSP responder mediante un nombre X500. */
		BY_NAME, 
		/** Por clave: una cadena en base64 de la clave pública del OCSP responder. */
		BY_KEY
	}

	/**
	 * <p>Devuelve una cadena que identifica al OCSP Responder que genera la respuesta.</p>
	 * 
	 * @return Cadena que identifica al OCSP Responder
	 */
	String getResponderID();
	
	/**
	 * <p>Devuelve el tipo de OCSP responder que ha generado la respuesta.</p> 
	 * 
	 * @return Tipo de OCSP responder
	 */
	TYPE_RESPONDER getResponderType();
	
	/**
	 * <p>Devuelve la fecha de la respuesta.</p>
	 * 
	 * @return fecha de generación de la respuesta
	 */
	Date getResponseDate();
	
}
