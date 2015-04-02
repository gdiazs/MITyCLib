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
package es.mityc.firmaJava.libreria.errores;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Excepción general del lado del cliente
 *
 */
public class ClienteError extends Exception { 
    
	String mensaje = ConstantesXADES.CADENA_VACIA;
     
	/**
     * Crea una nueva instancia de ClienteError sin el mensaje de detalle
     */
    public ClienteError() {
    }
    
    /**
     * Crea una nueva instancia de ClienteError con el mensaje de detalle
     * @param msg Detalle del mensaje
     */
    public ClienteError(String msg)
    {
        super(msg);
        this.mensaje = msg;
    }

    /**
     * Crea una nueva instancia de ClienteError
     * @param msg Excepción a propagar
     */
    public ClienteError(Throwable msg)
    {
        super(msg);
        this.mensaje = msg.getMessage() ;
    }
    
    public ClienteError(String msg, Throwable th) {
    	super(msg, th);
    	this.mensaje = msg;
    }
    
    /**
     * Este método obtiene el mensaje
     * @return mensaje Obtiene el mensaje
     */ 
    public String getMessage()
    {
        return mensaje ;
    }
}
