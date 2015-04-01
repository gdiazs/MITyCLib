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
package es.mityc.javasign.tsa;

import es.mityc.javasign.exception.SignMITyCException;

/**
 *  <p>Lanzada cuando produce un error a la hora de generar un sello de tiempo.</p>
 *  
 */
public class TimeStampException extends SignMITyCException {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     * <p>Constructor.</p>
     */
    public TimeStampException() {
        super();
    }

    /**
     * <p>Constructor.</p>
     * @param message Mensaje de error
     */
    public TimeStampException(final String message) {
        super(message);
    }

    /**
     * <p>Constructor.</p>
     * @param cause Causa de la excepción
     */
    public TimeStampException(final Throwable cause) {
        super(cause);
    }

    /**
     * <p>Constructor.</p>
     * @param message Mensaje de error
     * @param cause Causa de la excepción
     */
    public TimeStampException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
