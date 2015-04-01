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
 * <p>Manager devuelto cuando no se dispone de un diccionario asociado.</p>
 * 
 * <p>Esta clase evita que se produzcan errores en ejecución si no se controlan errores al instanciar el manager.</p>
 * 
 */
public class I18nDumbManager implements II18nManager {
	
	/** Espacio en blanco. */
	private static final String SPACE = " ";
	/** Cabecera fija del mensaje del internacionalizador. */
	private static final String DUMB_MESSAGE = "I18nDumbManager: no dictionary avalaible: ";
	
	/** Respuesta enviada como cabecera de todas las consultas a este internacionalizador. */
	private String response;
	
	/**
	 * <p>Construye una instancia de un manager no disponible.</p>
	 */
	public I18nDumbManager() {
	}
	
	/**
	 * <p>Inicializa el diccionario con el nombre del diccionario que se ha pedido.</p>
	 * @param dictionary Nombre del diccionario que no se ha encontrado
	 * @param locale Localizador con el que se inicializa el manager
	 * @throws DictionaryUnknownException No se lanza nunca
	 */
	public void init(final String dictionary, final Locale locale) throws DictionaryUnknownException {
		response = DUMB_MESSAGE + dictionary;
		if (locale != null) {
			response = response + SPACE + locale;
		}
	}

	/**
	 * <p>Devuelve un mensaje de aviso de que el diccionario no se encuentra disponible.</p>
	 * @param message Clave del mensaje que se quiere internacionalizar
	 * @return mensaje de aviso del error
	 * @see es.mityc.javasign.i18n.II18nManager#getLocalMessage(java.lang.String)
	 */
	public String getLocalMessage(final String message) {
		return response + SPACE + message;
	}

	/**
	 * <p>Devuelve un mensaje de aviso de que el diccionario no se encuentra disponible.</p>
	 * @param message Clave del mensaje que se quiere internacionalizar
	 * @param varargs variables que se quieren introducir en el mensaje
	 * @return mensaje de aviso del error
	 * @see es.mityc.javasign.i18n.II18nManager#getLocalMessage(java.lang.String, java.lang.Object[])
	 */
	public String getLocalMessage(final String message, final Object... varargs) {
		return response + SPACE + message;
	}

}
