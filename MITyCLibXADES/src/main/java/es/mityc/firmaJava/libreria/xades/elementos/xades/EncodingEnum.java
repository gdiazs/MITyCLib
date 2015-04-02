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
package es.mityc.firmaJava.libreria.xades.elementos.xades;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 */
public enum EncodingEnum {
	
	DER_ENCODED("http://uri.etsi.org/01903/v1.2.2#DER"),
	BER_ENCODED("http://uri.etsi.org/01903/v1.2.2#BER"),
	CER_ENCODED("http://uri.etsi.org/01903/v1.2.2#CER"),
	PER_ENCODED("http://uri.etsi.org/01903/v1.2.2#PER"),
	XER_ENCODED("http://uri.etsi.org/01903/v1.2.2#XER");
	
	private final static Log logger = LogFactory.getLog(EncodingEnum.class);
	
	private URI uri;
	
	private EncodingEnum(String uri) {
		try {
			this.uri = new URI(uri);
		} catch (URISyntaxException ex) {
			Log logger = LogFactory.getLog(EncodingEnum.class);
			logger.error("Error creando enumerado de encoding", ex);
		}
	}
	
	public URI getEncodingUri() {
		return uri;
	}
	
	public static EncodingEnum getEncoding(String uri) {
		try {
			if ((uri == null) || ("".equals(uri.trim())))
					return DER_ENCODED;
			URI temp = new URI(uri);
			if (temp.equals(DER_ENCODED.uri))
				return DER_ENCODED;
			else if (temp.equals(BER_ENCODED.uri))
				return BER_ENCODED;
			else if (temp.equals(CER_ENCODED.uri))
				return CER_ENCODED;
			else if (temp.equals(PER_ENCODED.uri))
				return PER_ENCODED;
			else if (temp.equals(XER_ENCODED.uri))
				return XER_ENCODED;
		} catch (URISyntaxException ex) {
			if (logger.isDebugEnabled())
				logger.debug("Encoding indicado no es una URI", ex);
			return null;
		}
		return null;
	}

}
