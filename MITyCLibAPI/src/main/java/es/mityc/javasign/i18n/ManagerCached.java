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
 * <p>Soporte de internacionalizador cacheado.</p>
 * <p>Permite optimizar el acceso a internacionalizadores cacheando un manager de un diccionario con el locale relativo.</p>
 */
class ManagerCached {
	/** Manager de internacionalización. */
	private II18nManager managerCached;
	/** Locale del internacionalizador. */
	private Locale localeCached;
	/**
	 * <p>Constructor.</p>
	 * @param manager Manager de internacionalización
	 * @param i18nLocale Locale del manager
	 */
	public ManagerCached(final II18nManager manager, final Locale i18nLocale) {
		this.managerCached = manager;
		this.localeCached = i18nLocale;
	}
	/**
	 * <p>Devuelve si el locale indicado es el mismo que el del manager cacheado.</p>
	 * @param otherLocale Localizador a comparar
	 * @return <code>true</code> si es el mismo locale, <code>false</code> en otro caso
	 */
	public boolean isSameLocale(final Locale otherLocale) {
		if (otherLocale == null) {
			if (this.localeCached == null) {
				return true;
			}
			return false;
		}
		return otherLocale.equals(this.localeCached);
	}
	/**
	 * <p>Devuelve el manager asociado a esta caché.</p>
	 * @return internacionalizador
	 */
	public II18nManager getI18nCached() {
		return managerCached;
	}
}
