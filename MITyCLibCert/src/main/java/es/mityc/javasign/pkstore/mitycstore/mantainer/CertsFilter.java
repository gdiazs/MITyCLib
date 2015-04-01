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
package es.mityc.javasign.pkstore.mitycstore.mantainer;

import java.io.File;

import javax.swing.filechooser.FileFilter;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
* Clase que extiende de FileFilter para filtrar ficheros con certificados. 
*/
public class CertsFilter extends FileFilter {
    
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	/** Extensión para los contenedores PKCS12. */
	private static final String P12	= "p12";
	/** Extensión para certificados. */
	private static final String CER	= "cer";
	/** Extensión para certificados. */
	private static final String CRT	= "crt";
	/** Caracter de separación entre nombre y extensión. */
    private static final char CHAR_DOT = '.';
    /** Booleano para indicar si el certificado debe estar asociado a una clave privada. */
    private boolean isSign = false;
    
    /**
     * <p>Constructor del filtro para certificados.</p>
     * @param isCertForSign <p>Parámetro que indica si el filtro es para certificados de firma o de autenticación.
     * 		  <code>true</code> indica que es certificado de firma, por lo que se incluyen las extensiones P12.</p>
     */
    public CertsFilter(boolean isCertForSign) {
    	super();
    	this.isSign = isCertForSign;
    }
    
    /**
     * <p>Este método filtra las extensiones de los ficheros que contienen certificados.</p>
     * @param f Fichero o directorio a filtrar
     * @return <code>true</code> indica que se pasa el filtro.
     */    
    @Override
    public boolean accept(final File f) {

        if (f.isDirectory()) {
            return true;
        }

        String s = f.getName();
        int i = s.lastIndexOf(CHAR_DOT);

        if (i > 0  &&  i < s.length() - 1) {
            String extension = s.substring(i + 1).toLowerCase();
            if (P12.equals(extension) && isSign) {
            	return true;
            } else if (CER.equals(extension)) {
                return true;
            } else if (CRT.equals(extension)) {
            	return true;
            } else {
                return false;
            }
        }

        return false;
    }
    
    
    /**
     * <p>Descripción del filtro de certificados.</p>
     * @return Se devuelve el nombre a mostrar para el filtro
     */
    @Override
    public String getDescription() {
    	// Certificados
    	return I18N.getLocalMessage(ConstantsCert.I18N_CERT_MITYC_46);
    }
}
