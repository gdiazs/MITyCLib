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
 * Excepción general en el XML
 *
 */

public class XMLError extends Exception {
    
    /**
     * Crea una nueva instancia de XMLError sin el detalle mensaje
     */
    public XMLError() {
    }

    /**
     * Crea una instancia de XMLError con el detalle de mensaje especificado
     * @param msg El detalle mensaje
     */
    public XMLError(String msg) {
        super(msg);
    }
    
	public XMLError(String message, Throwable cause) {
		super(message, cause);
	}

	public XMLError(Throwable cause) {
		super(cause);
	}
    
    
}
