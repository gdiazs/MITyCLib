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
package es.mityc.firmaJava.libreria.xades;

/**
 * Esquemas de firma XAdES
 * 
 */

public enum XAdESSchemas implements Comparable<XAdESSchemas> {

	XAdES_111("1.1.1", "http://uri.etsi.org/01903/v1.1.1#"),
	XAdES_122("1.2.2", "http://uri.etsi.org/01903/v1.2.2#"),
	XAdES_132("1.3.2", "http://uri.etsi.org/01903/v1.3.2#"),
	XAdES_141("1.4.1", "http://uri.etsi.org/01903/v1.4.1#"),
	XAdES_142("1.4.2", "http://uri.etsi.org/01903/v1.4.2#"),
	XMLDSIG("xmldsig", "http://www.w3.org/2000/09/xmldsig#"),
	OTHER("", "");

	private String name;
	private String uri;

	private XAdESSchemas(String name, String uri) {
		this.name = name;
		this.uri = uri;
	}
	
	public String getSchemaVersion() {
		return name;
	}

	@Override
	public String toString() {
		return name;
	}

	public String getSchemaUri() {
		return uri;
	}
	
	public static XAdESSchemas getXAdESSchema(String esquemaUri) {
		XAdESSchemas resultado = null;
		if (esquemaUri != null) {
			if (XAdES_111.uri.equals(esquemaUri)) {
				resultado = XAdES_111;
			} else if (XAdES_122.uri.equals(esquemaUri)) {
				resultado = XAdES_122;
			} else if (XAdES_132.uri.equals(esquemaUri)) {
				resultado = XAdES_132;
			} else if (XMLDSIG.uri.equals(esquemaUri)) {
				resultado = XMLDSIG;
			} else {
			    resultado = OTHER;
			}
		}
		return resultado;
	}
}


