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
package es.mityc.firmaJava.libreria.utilidades;

import java.util.Locale;
import java.util.ResourceBundle;

import es.mityc.firmaJava.libreria.ConstantesXADES;


/**
 * Clase que permite la internacionalización de las cadenas de texto de la aplicación
 *
 */
public class I18n { 
	
    private static Locale locale = new Locale(ConstantesXADES.DEFAULT_LOCALE,ConstantesXADES.DEFAULT_LOCALE.toUpperCase());

    
    /**
     * Obtiene el valor de una cadena definida para el idioma por defecto configurado
     * @param clave Clave que identifica la cadena de texto
     * @return cadena traducida para un determinado idioma
     */
    public static String getResource(String clave)
    {
        return getResource(clave, locale) ;
    }
    
    
    /**
     * Obtiene el valor de una cadena definida para el idioma pasado por parametro en el Locale
     * @param clave Clave que identifica la cadena de texto
     * @param locale Locale del idioma del cual queremos la traduccion
     * @return cadena traducida para un determinado idioma
     */
    public static String getResource(String clave, Locale locale)
    {
        return ResourceBundle.getBundle(ConstantesXADES.LOCALE_FILES, locale).getString(clave) ;
    }
    
    
    /**
     * Obtiene el Locale que se utiliza en ese momento
     * @return Locale que se utiliza en ese momento
     */
    public static Locale getLocale() 
    {
        return locale;
    }
    
    
    /**
     * Asigna el Locale que se utilizara en las traducciones
     * @param pais Pais
     * @param dialecto Dialecto del idioma
     */
    public static void setLocale(String pais, String dialecto) 
    {
        locale = new Locale(pais, dialecto);
    }

}
