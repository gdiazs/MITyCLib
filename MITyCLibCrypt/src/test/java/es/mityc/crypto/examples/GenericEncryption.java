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
package es.mityc.crypto.examples;

/**
 * <p>
 * Clase base que deberían extender los diferentes ejemplos para realizar encriptaciones
 * XML.
 * </p>
 * 
 */
public abstract class GenericEncryption {

	protected String DATA_TO_ENCRYPT = "Hola mundo";
	    /**
	     * <p>
	     * Ejecución del ejemplo. La ejecución consistirá en la encriptación de los datos
	     * de <code>DATA_TO_ENCRYPT</code>. Se retornará elresultado del proceso de encriptación
	     * </p>
	     */
	    protected void execute() {
	    	// Encriptamos
	    	System.out.println("Texto original:"+DATA_TO_ENCRYPT);
	    	char [] encrypted=encrypt(DATA_TO_ENCRYPT);
	    	System.out.println("Texto encriptado:"+new String(encrypted));
	    	String clear=decrypt(encrypted);
	    	System.out.println("Texto recuperado:"+clear);
	    }

	    /**
	     * <p>
	     * Realiza la encriptación
	     * </p>
	     * 
	     * @return Cadena encriptada
	     */
	    protected abstract char [] encrypt(String cadena);

	    /**
	     * <p>
	     * Realiza la desencriptación
	     * </p>
	     * 
	     * @return Cadena desencriptada
	     */
	    protected abstract String decrypt(char[] cadena);

	}
