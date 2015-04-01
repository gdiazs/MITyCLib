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
package es.mityc.firmaJava.ocsp.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/** 
 * Proporciona acceso a la lista de proveedores OCSP's configurados
 */

public class ConfigProveedoresResolver implements EntityResolver, ConstantesProveedores {

	public InputSource resolveEntity(String arg0, String arg1)
			throws SAXException, IOException {

		InputSource sourceXsd = null;
		File XsdUpdated = new File (System.getProperty(USERDIR) + SEPARATOR + XSD_FILE);
		InputStream sXsd = null;
			
		if (XsdUpdated.exists()) {
			sXsd = new FileInputStream (XsdUpdated);
		} else {
			sXsd = getClass().getResourceAsStream(XSD_DEFAULT_FILE);
		}
		sourceXsd = new InputSource(sXsd);
		
		return sourceXsd;
	}

}
