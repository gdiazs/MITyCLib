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
package es.mityc.firmaJava.ocsp;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * Clase que permite la internacionalizacion de las cadenas de texto de la aplicacion
 *
 */

public class I18n implements ConstantesOCSP{
    private static Locale locale = new Locale(ES_MINUSCULA,ES_MAYUSCULA);
    
    
    /**
     * Obtiene el valor de una cadena definida para el idioma por defecto configurado
     * @param key Clave que identifica la cadena de texto
     * @return cadena traducida para un determinado idioma
     */
    public static String getResource(String key){
        return getResource(key,locale) ;
    }
    /**
     * Obtiene el valor de una cadena definida para el idioma pasado por parametro en el Locale
     * @param key Clave que identifica la cadena de texto
     * @param locale Locale del idioma del cual queremos la traduccion
     * @return cadena traducida para un determinado idioma
     */
    public static String getResource(String key,Locale locale){
        return ResourceBundle.getBundle(NOMBRE_LIBRERIA,locale).getString(key) ;
    }
    /**
     * Obtiene el Locale que se utiliza en ese momento
     * @return Locale que se utiliza en ese momento
     */
    public static Locale getLocale() {
        return locale;
    }
    /**
     * Asigna el Locale que se utilizara en las traducciones
     * @param locale Locale que se utilizara en las traducciones
     */
    public static void setLocale(Locale _locale) {
        locale = _locale;
    }
    /**
     * Asigna el Locale que se utilizara en las traducciones
     * @param country Pais
     * @param dialect Dialecto del idioma
     */
    public static void setLocaleCountry(String country,String dialect) {
        locale = new Locale(country,dialect);
    }
}

