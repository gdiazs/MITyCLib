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
package es.mityc.javasign.pass;

/**
 * <p>Interfaz que han de cumplir los ofuscadores de información.</p>
 * <p>Este interfaz permite definir una manera común y sencilla de ofuscar información de pequeño tamaño.</p>
 */
public interface IPassSecurity {
	
	/**
	 * <p>Protege un conjunto pequeño de datos produciendo un resultado ofuscado.</p>
	 * @param pass datos a proteger
	 * @return resultado ofuscado
	 * @throws PassSecurityException lanzada si se produce un error en el ofuscamiento
	 */
	String protect(String pass) throws PassSecurityException;
	
	/**
	 * <p>Recupera información ofuscada con el método anterior produciendo un resultado claro.</p>
	 * @param pass Información ofuscada
	 * @return información clara
	 * @throws PassSecurityException lanzada si se produce un error al eliminar el ofuscamiento
	 */
	String recover(String pass) throws PassSecurityException;

}
