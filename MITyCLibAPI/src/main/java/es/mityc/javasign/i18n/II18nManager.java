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
package es.mityc.javasign.i18n;

import java.util.Locale;

/**
 * <p>Interfaz que han de implementar los managers de internacionalización.</p>
 * 
 */
public interface II18nManager {
	
	/**
	 * Inicializa el manager con el diccionario indicado.
	 * 
	 * @param dictionary diccionario que deberá gestionar el manager
	 * @param locale Locale establecido (<code>null</code> si no se especifica ninguno)
	 * @throws DictionaryUnknownException cuando se desconoce el diccionario indicado
	 */
	void init(String dictionary, Locale locale) throws DictionaryUnknownException;

	/**
	 * <p>Devuelve el mensaje identificado por la clave proporcionada según el diccionario gestionado por el manager.</p>
	 *  
	 * @param message clave que identifica el mensaje
	 * @return mensaje recuperado
	 */
	String getLocalMessage(String message);

	/**
	 *<p> Devuelve el mensaje compuesto identificado por la clave proporcionada según el diccionario gestionado por el manager.</p>
	 *  
	 * @param message clave que identifica el mensaje
	 * @param varargs variables que se deben insertar en el mensaje compuesto
	 * @return mensaje recuperado con las variables indicadas incrustadas
	 */
	String getLocalMessage(String message, Object... varargs);

}
