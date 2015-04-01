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
package es.mityc.javasign.certificate.ocsp;

/**
 * <p>Clase de constantes de la librería base.</p>
 * 
 */
public final class ConstantsOCSP {
	
	/**
	 * Constructor.
	 */
	private ConstantsOCSP() { }
	
	/** Nombre de la librería. */
	public static final String LIB_NAME = "MITyCLibOCSP";
    
    /** Propiedad de la configuración que señala el servidor OCSP al que consultar. */
	public static final String OCSP_SERVER_URL = "OCSPserverURL";
	
	/** No se pudo recuperar el certificado emisor de: {0}.*/
	public static final String OCSP_LIST_ERROR_1 = "i18n.mityc.ocsp.list.1";
}
