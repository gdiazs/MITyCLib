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
package es.mityc.firmaJava.libreria.xades;

import java.util.ArrayList;
import java.util.Iterator;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 */
public class ValidationResult { 
	
	private boolean validado;
	private ArrayList log;
	
	/**
	 * Crea una nueva instancia de ValidationResult()
	 */
	public ValidationResult()
	{
		this.validado 	= false;
		this.log		= new ArrayList<String>();
	}
	
	/**
	 * Obtener el valor de log
	 * @return
	 */
	public ArrayList getLog() {
		return log;
	}
	
	/**
	 * Establece el valor de log
	 * @param log
	 */
	public void setLog(ArrayList log) {
		this.log = log;
	}
	
	/**
	 * Obtener el valor de validado
	 * @return
	 */
	public boolean isValidate() {
		return validado;
	}
	
	/**
	 * Devuelve el valor de validado
	 * @param validado
	 */
	public void setValidate(boolean validado) {
		this.validado = validado;
	}
	
	/**
	 * Este metodo añade un nuevo log a la lista
	 */
	public void addLog(String log)
	{
		this.log.add(log);
	}
	
	/**
	 * Esta clase devuelve todos los logs insertados
	 * @return
	 */
	public String writeLog()
	{
		StringBuffer log = new StringBuffer();
		for(Iterator<String> it = this.log.iterator(); it.hasNext(); )
		{
			String _log = it.next();
			log.append(_log);
			log.append(ConstantesXADES.NUEVA_LINEA);
 		}
		return log.toString();
	}

}
