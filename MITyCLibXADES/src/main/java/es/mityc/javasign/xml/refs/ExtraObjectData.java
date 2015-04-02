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

import java.net.URI;

/**
 * <p>Guarda información extra sobre codificación y MIME de un objeto.</p>
 */
public class ExtraObjectData {
	
	/** Tipo mime del objeto. */
	private String mimeType = null;
	/** Tipon de encoding en el que se encuentra el objeto. */
	private URI encoding = null;
	
	/**
	 * <p>Constructor.</p>
	 * @param mimeType Tipo mime del objeto 
	 * @param encoding Encoding del objeto (en formato URI) 
	 */
	public ExtraObjectData(String mimeType, URI encoding) {
		super();
		this.mimeType = mimeType;
		this.encoding = encoding;
	}

	/**
	 * @return the mimeType
	 */
	public String getMimeType() {
		return mimeType;
	}

	/**
	 * @return the encoding
	 */
	public URI getEncoding() {
		return encoding;
	}
}
