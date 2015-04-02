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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Manejador de errores de PKCS12
 */

public class PKCS12Error extends Exception{
	
	static Log log = LogFactory.getLog(PKCS12Error.class);
     
    /**
     * Crea una nueva instancia de un error PKCS12
     * @param causa causa del error
     */
    public PKCS12Error(String causa) {
		super(causa);
        log.error(causa);
    }
    
    
    /**
     * Crea una nueva instancia de un error PKCS12
     * @param e excepción
     */ 
    public PKCS12Error(Exception e)
    {
    	log.error(e.getMessage());
    }
    
    @Override
    public String toString(){
    	return super.toString();
    }

}
