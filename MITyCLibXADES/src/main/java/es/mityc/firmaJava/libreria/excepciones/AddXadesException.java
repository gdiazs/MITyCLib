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
package es.mityc.firmaJava.libreria.excepciones;

/**
 * Manejador de errores 
 */

public class AddXadesException extends Exception {

	/**
     * Crea una nueva instancia de AddXadesException sin el mensaje de detalle
     */
	public AddXadesException() {
	}

	/**
     * Crea una nueva instancia de AddXadesException con el mensaje de detalle
     */
	public AddXadesException(String message) {
		super(message);
	}

	/**
     * Crea una nueva instancia de AddXadesException con la causa
     */
	public AddXadesException(Throwable cause) {
		super(cause);

	}

	/**
     * Crea una nueva instancia de AddXadesException con el mensaje de detalle y la causa
     */
	public AddXadesException(String message, Throwable cause) {
		super(message, cause);
	}

}
