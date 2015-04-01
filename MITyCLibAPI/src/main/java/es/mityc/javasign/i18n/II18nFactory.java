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
 * Interfaz que ha de implementar una factoría de managers de internacionalización.
 * 
 */
public interface II18nFactory {

	/**
	 * Devuelve una instancia de un manager de internacionalización.
	 * 
	 * @param dictionary Clave que identifica el diccionario
	 * @param locale Localización de la que se quiere el diccionario
	 * @return Instancia del manager de internacionalización
	 */
	II18nManager getI18nManager(String dictionary, Locale locale);

}
