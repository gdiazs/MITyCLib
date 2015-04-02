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
package es.mityc.firmaJava.libreria.xades.errores;

/**
 * Excepcion para indicar que hay un error en la validación de una policy 
 *
 */

public class PolicyException extends FirmaXMLError {

	public PolicyException() {
	}

	public PolicyException(String msg) {
		super(msg);
	}

	public PolicyException(Exception e) {
		super(e);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public PolicyException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param cause
	 */
	public PolicyException(Throwable cause) {
		super(cause);
	}
	
	

}
