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

/**
 * Constantes para los proveedores OCSP's
 */

public interface ConstantesProveedores {
	static final Object NODO_PROVEEDORES = "proveedores";
	static final Object NODO_VERSION = "version";
	static final Object NODO_FECHA = "fecha";
	static final Object NODO_PROVEEDOR = "proveedor";
	static final Object NODO_CA = "ca";
	static final Object NODO_OCSP = "servidorOCSP";
	static final String ATT_NOMBRE = "nombre";
	static final String ATT_NAMEHASH = "nameHash";
	static final String ATT_PKHASH = "pkHash";
	static final String ATT_DESCRIPCION = "descripcion";
	static final String ATT_URI = "URI";
	static final String FEATURE_NAMESPACES = "http://xml.org/sax/features/namespaces";
	static final String FEATURE_VALIDATION = "http://xml.org/sax/features/validation";
	static final String FEATURE_SCHEMA = "http://apache.org/xml/features/validation/schema";
	static final String FEATURE_EXTERNALSCHEMA = "http://apache.org/xml/properties/schema/external-schemaLocation";
	static final String XML_FILE = "OCSPServersInfo.xml";
	static final String XSD_FILE = "OCSPServersInfo.xsd";
	static final String SEPARATOR = "/";
	static final String EMPTY_STRING = "";
	static final String ALMOHADILLA = "#";
	static final String XML_DEFAULT_FILE = SEPARATOR + XML_FILE;
	static final String XSD_DEFAULT_FILE = SEPARATOR + XSD_FILE;
	static final String USERDIR = "user.dir";
	static final String IO_EXCEPTION = "IOException ";
	static final String CERTIFICATE_EXCEPTION = "IOException ";
	static final String INVALID_URI = "Invalid Uri. ";
	static final String CERTIFICATE_TYPE_EXCEPTION = "Illegal argument type. Can be a String, byte[] or X509Certificate.";
	static final String X_509 = "X.509";
}
