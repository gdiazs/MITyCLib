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
/**
 * 
 */
package es.mityc.javasign.pkstore.mitycstore;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * Clase de utilidades para el acceso a certificados.
 * 
 */
public final class CertUtil {
	
	/** Clase de utilidades estáticas. Constructor privado. */
	private CertUtil() { }
	
	/**
	 * Extrae una cadena con el nombre disponible en un Distinguished Name (DN).
	 * 
	 * Para la extracción del nombre se busca en primer lugar el contenido del campo CN del DN. Si no existe se busca el campo OU y si
	 * este no existe se busca el campo O.
	 * 
	 * @param dname Distinguished Name del que se extraerá el nombre
	 * @return Cadena procesada con un nombre más simple, <c>null</c> si no se ha encontrado un nombre simplificado.
	 */
	public static String extractName(final X500Principal dname) {
		return extractName(dname.getName());
	}
	
	/**
	 * Extrae una cadena con el nombre disponible en un Distinguished Name (DN).
	 * 
	 * Para la extracción del nombre se busca en primer lugar el contenido del campo CN del DN. Si no existe se busca el campo OU y si 
	 * este no existe se busca el campo O.
	 * 
	 * @param dname Distinguished Name del que se extraerá el nombre
	 * @return Cadena procesada con un nombre más simple, <c>null</c> si no se ha encontrado un nombre simplificado
	 */
	public static String extractName(final String dname) {
		String res = null;
		String[] col = splitAttributes(dname);
		res = searchAttribute(col, "CN");
		if (res == null) {
			res = searchAttribute(col, "OU");
		}
		if (res == null) {
			res = searchAttribute(col, "O");
		}
		return res;
	}
	
	/**
	 * <p>Busca el atributo indicado de entre los elementos de la colección proporcionada.</p>
	 * @param col Colección de cadenas de texto, origen de los datos
	 * @param att Atributo a buscar
	 * @return El atributo encontrado ó <code>null</code> si no se encontró
	 */
	private static String searchAttribute(final String[] col, final String att) {
		String res = null;
		String attmod = att.toLowerCase() + "=";
		for (int i = 0; i < col.length; i++) {
			if (col[i].trim().toLowerCase().startsWith(attmod)) {
				res = col[i].trim().substring(attmod.length());
				break;
			}
		}
		return res;
	}
	
	/**
	 * <p>Separa las distintas partes, separadas por comas, de las que se compone el String proporcionado.</p>
	 * @param dname String a separar en partes
	 * @return Array de String con las partes obtenidas
	 */
	private static String[] splitAttributes(final String dname) {
		List<String> results = new ArrayList<String>();
		String[] col = dname.split(",");
		for (int i = 0; i < col.length; i++) {
			String piece = col[i];
			while (i < col.length - 1) {
				if (!col[i + 1].contains("=")) {
					piece += "," + col[++i];
				} else {
					break;
				}
			}
			results.add(piece);
		}
		return results.toArray(new String[0]);
	}
	
	 /**
     * <p>Convierte un java.util.Date a DateFormat.SHORT.</p>
     * @param date Fecha a convertir
     * @return String en formato DateFormat.SHORT,new Locale("ES","es")
     */
    public static String convertDate(final Date date) {
        DateFormat formatoFecha = DateFormat.getDateInstance(DateFormat.SHORT);
        String fecha = formatoFecha.format(date);
        
        return fecha.replace("/", "-");
    }
}
