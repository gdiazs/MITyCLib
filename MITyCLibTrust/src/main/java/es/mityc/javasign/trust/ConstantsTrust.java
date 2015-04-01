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
package es.mityc.javasign.trust;

/**
 * <p>Constantes de la librería de confianza.</p>
 * 
 */
public final class ConstantsTrust {
	
	/**
	 * Constructor.
	 */
	private ConstantsTrust() { }
	
	/** Nombre de la librería. */
	public static final String LIB_NAME = "MITyCLibTrust";
	
	/** Clave que identifica el validador de confianza de entidades permitidas por MITyC. */
	public static final String KEY_MITYC = "mityc";
	
	/** Truster obtenido no es de certificados de firma.*/
	public static final String I18N_TRUST_1 = "i18n.mityc.trust.1";
	/** Truster obtenido no es de emisores de CRLs.*/
	public static final String I18N_TRUST_2 = "i18n.mityc.trust.2";
	/** Truster obtenido no es de respuestas OCSP.*/
	public static final String I18N_TRUST_3 = "i18n.mityc.trust.3";
	/** Truster obtenido no es de sellos de tiempo.*/
	public static final String I18N_TRUST_4 = "i18n.mityc.trust.4";
	/** Truster obtenido no es de validación general.*/
	public static final String I18N_TRUST_5 = "i18n.mityc.trust.5";

	/** No hay fichero de configuración disponible: {0}.*/
	public static final String I18N_TRUST_PROPS_1 = "i18n.mityc.trust.props.1";
	/** No se puede obtener clave pública de certificado emisor: {0}.*/
	public static final String I18N_TRUST_PROPS_2 = "i18n.mityc.trust.props.2";
	/** CRL tiene errores de codificación: {0}.*/
	public static final String I18N_TRUST_PROPS_3 = "i18n.mityc.trust.props.3";
	/** No se encuentra algoritmo de firma para validar CRL: {0}.*/
	public static final String I18N_TRUST_PROPS_4 = "i18n.mityc.trust.props.4";
	/** No se encuentra provider para validar firma de CRL: {0}.*/
	public static final String I18N_TRUST_PROPS_5 = "i18n.mityc.trust.props.5";
	/** No se encuentra provider para validar sello TSA: {0}.*/
	public static final String I18N_TRUST_PROPS_6 = "i18n.mityc.trust.props.6";
	/** Error en la validación de un sello TSA: {0}.*/
	public static final String I18N_TRUST_PROPS_7 = "i18n.mityc.trust.props.7";
	/** Certificado indicado no se encuentra como recurso: {0}.*/
	public static final String I18N_TRUST_PROPS_8 = "i18n.mityc.trust.props.8";
	/** Factoría de certificados no disponible: {0}.*/
	public static final String I18N_TRUST_PROPS_9 = "i18n.mityc.trust.props.9";
	/** Error recuperando certificado de recursos: {0}.*/
	public static final String I18N_TRUST_PROPS_10 = "i18n.mityc.trust.props.10";
	/** Error recuperando respuesta BasicResponse: {0}.*/
	public static final String I18N_TRUST_PROPS_11 = "i18n.mityc.trust.props.11";
	/** Error recuperando certificados de firma de BasicResponse: {0}.*/
	public static final String I18N_TRUST_PROPS_12 = "i18n.mityc.trust.props.12";
	/** Error recuperando identidad de firmante de BasicResponse: {0}.*/
	public static final String I18N_TRUST_PROPS_13 = "i18n.mityc.trust.props.13";
	/** No se encuentra provider para validar respuesta OCSP: {0}.*/
	public static final String I18N_TRUST_PROPS_14 = "i18n.mityc.trust.props.14";
	/** Error en la validación de una respuesta OCSP: {0}.*/
	public static final String I18N_TRUST_PROPS_15 = "i18n.mityc.trust.props.15";
	/** Certificado tiene errores de codificación: {0}.*/
	public static final String I18N_TRUST_PROPS_16 = "i18n.mityc.trust.props.16";
	/** No se encuentra algoritmo de firma para validar certificado: {0}.*/
	public static final String I18N_TRUST_PROPS_17 = "i18n.mityc.trust.props.17";
	/** No se encuentra provider para validar firma de certificado: {0}.*/
	public static final String I18N_TRUST_PROPS_18 = "i18n.mityc.trust.props.18";
	/** Error recuperando certificados de sello de tiempo: {0}.*/
	public static final String I18N_TRUST_PROPS_19 = "i18n.mityc.trust.props.19";
	/** Error recuperando almacenes de certificados de truster: {0}.*/
	public static final String I18N_TRUST_PROPS_20 = "i18n.mityc.trust.props.20";
	/** Error recuperando los certificados de CRLs: {0}.*/
	public static final String I18N_TRUST_PROPS_21 = "i18n.mityc.trust.props.21";
	/** Error recuperando los certificados de OCSP: {0}.*/
	public static final String I18N_TRUST_PROPS_22 = "i18n.mityc.trust.props.22";
	/** Error verificando cadena de emisores: {0}.*/
	public static final String I18N_TRUST_PROPS_23 = "i18n.mityc.trust.props.23";
	/** Error recuperando los certificados de firmantes: {0}.*/
	public static final String I18N_TRUST_PROPS_24 = "i18n.mityc.trust.props.24";
	/** Error recuperando los certificados de TSA: {0}.*/
	public static final String I18N_TRUST_PROPS_25 = "i18n.mityc.trust.props.25";
	/** El sello de tiempo fue emitido fuera del periodo de validez del emisor.*/
	public static final String I18N_TRUST_PROPS_26 = "i18n.mityc.trust.props.26";
	
	/** Fatan parámetros de entrada. */
	public static final String I18N_TRUST_UTILS_1 = "i18n.mityc.trust.utils.1";
	/** No se pudo guardar la configuracion de confianza protegida. */
	public static final String I18N_TRUST_UTILS_2 = "i18n.mityc.trust.utils.2";
}
