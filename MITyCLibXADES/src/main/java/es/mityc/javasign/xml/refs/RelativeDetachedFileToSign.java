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
package es.mityc.javasign.xml.refs;

import java.io.File;
import java.util.Map;

import es.mityc.javasign.certificate.ElementNotFoundException;
import es.mityc.javasign.certificate.IRecoverElements;
import es.mityc.javasign.certificate.UnknownElementClassException;

/**
 * Representa un objeto externo (en forma de fichero) al XML que debe ser firmado.
 */
public class RelativeDetachedFileToSign extends AbstractObjectToSign implements IRecoverElements {
	
	private File file;
	
	public RelativeDetachedFileToSign(File file) {
		this.file = file;
	}
	
	/**
	 * @return the file
	 */
	public File getFile() {
		return file;
	}

	/**
	 * @param file the file to set
	 */
	public void setFile(File file) {
		this.file = file;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getReferenceURI()
	 */
	@Override
	public String getReferenceURI() {
		return "." + File.separator + file.getName();
	}

	@Override
	public <T> T getElement(Map<String, Object> props, Class<T> elementClass)
			throws ElementNotFoundException, UnknownElementClassException {
		return null;
	}
}
