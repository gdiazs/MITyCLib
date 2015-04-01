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
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * <p>Manager para la internacionalización que permite sobreescritura de frases.</p>
 * 
 * <p>Obtiene el diccionario buscando un fichero de propiedades con el mismo nombre que el diccionario la ruta de
 * recursos <code>/i18n/dictionaries</code> y con el tipo de Locale indicado. No se recarga si hay un cambio de Locale.</p>
 * <p>También busca un diccionario con el mismo nombre pero añadiéndole el sufijo <code>_add</code>. En caso de existir
 * buscará las claves en ese fichero antes que en el fichero base.</p>
 * 
 */
public class I18nAddendumManager extends I18nDefaultManager {

	/** Ruta donde se buscan los diccionarios. */
	protected static final String ADDENDUM_SUFIX = "_add";
	
	/** Recursos de internacionalización addendum asociados a este manager. */
	private ResourceBundle rbAdd = null;
	
	public static I18nAddendumManager newInstance() {
		return new I18nAddendumManager();
	}

	/**
	 * <p>Busca el diccionario indicado en la ruta <code>i18n/dictionaries</code> siguiendo el nombre del diccionario provisto como
	 * un recurso dependiente del locale (@see {@link ResourceBundle}) y añadiéndole el sufijo <code>add</code>.</p>
	 * 
	 * @param dictionary Nombre del diccionario que se asocia al manager
	 * @param specificLocale locale específico en el que se quiere el diccionario
	 * @throws DictionaryUnknownException Lanzada cuando no se encuentra el diccionario indicado
	 * @see es.mityc.javasign.i18n.II18nManager#init(java.lang.String, java.util.Locale)
	 */
	@Override
	public void init(final String dictionary, final Locale specificLocale) throws DictionaryUnknownException {
		super.init(dictionary, specificLocale);
		// busca el fichero extra de recursos de idioma en la carpeta i18n/dictionaries
		try {
			rbAdd = ResourceBundle.getBundle(BASE_PATH + dictionary + ADDENDUM_SUFIX, this.locale);
		} catch (MissingResourceException ex) {
		}
	}
	
	/**
	 * <p>Devuelve el mensaje asociado a la clave indicada.</p>
	 * <p>Busca el mensaje en el addenudum en primer lugar. Si no lo encuentra lo busca en el diccionario base.</p>
	 * @param key clave del mensaje
	 * @return Mensaje recuperado
	 */
	@Override
	protected String findMessage(final String key) {
		if (rbAdd != null) {
			try {
				return rbAdd.getString(key);
			} catch (MissingResourceException ex) {
			}
		}
		return super.findMessage(key);
	}
}
