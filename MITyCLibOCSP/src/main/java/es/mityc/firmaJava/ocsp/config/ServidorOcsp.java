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

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Contiene informacion sobre un servidor OCSP. 
 * 
 */

public class ServidorOcsp implements Cloneable, ConstantesProveedores{
	
	private URI url = null;
	private String descripcion = EMPTY_STRING; 
	
	/**
	 * Constructor de la clase
	 * @param url Url del OCSP Responder
	 * @param descripcion Breve descripcion del servidor
	 * @throws URISyntaxException Si la url no es valida.
	 */
	public ServidorOcsp(String url, String descripcion) throws URISyntaxException {
		this.url = new URI (url);
		this.descripcion = descripcion;
	}
	/**
	 * Obtiene la descripcion del servidor.
	 * @return
	 */
	public String getDescripcion() {
		return descripcion;
	}
	
	/**
	 * Obtiene la URL del OCSP Responder
	 */
	public URI getUrl() {
		return url;
	}
	protected Object clone() throws CloneNotSupportedException {
		return (ServidorOcsp) super.clone();
	}
}
