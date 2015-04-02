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
package es.mityc.javasign;

/**
 * Clase de constantes de la librería
 * 
 */
public class ConstantsXAdES {

	public static final String LIB_NAME = "MITyCLibXAdES";
	
	/** Nombre por defecto del namespace que se aplicará a nodos de XML Signature. */
	public static final String DEFAULT_NS_XMLSIG = "ds";
	/** Nombre por defecto del namespace que se aplicará a nodos de XAdES. */
	public static final String DEFAULT_NS_XADES = "etsi";
	/** Codificación por defecto del xml. */
	public static final String DEFAULT_XML_ENCODING = "UTF-8";
    
	// Contantes de internacionalización
	/** Algoritmo de resumen desconocido: {0}. */
	public static final String I18N_SIGN_1 = "i18n.mityc.xades.sign.1";
	/** No se puede construir la información sobre el objeto firmado. */
	public static final String I18N_SIGN_2 = "i18n.mityc.xades.sign.2";
	/** No se puede acceder a la ruta indicada para crear el fichero: {0}. */
	public static final String I18N_SIGN_3 = "i18n.mityc.xades.sign.3";
	/** Error escribiendo datos en fichero {1} en ruta {0}. */
	public static final String I18N_SIGN_4 = "i18n.mityc.xades.sign.4";
	/** No se puede establecer la dirección base indicada: {0}. */
	public static final String I18N_SIGN_5 = "i18n.mityc.xades.sign.5";
	/** Error almacenando certificado o estado de certificado ({1}): {0}. */
	public static final String I18N_SIGN_6 = "i18n.mityc.xades.sign.6";
	/** No se puede aplicar la transformada indicada en el objeto: {0}. */
	public static final String I18N_SIGN_7 = "i18n.mityc.xades.sign.7";
	/** Namespace de la hoja de estilo desconocido: {0}. */
	public static final String I18N_SIGN_8 = "i18n.mityc.xades.sign.8";
	/** Elemento de hoja de estilo no es "stylesheet": {0}. */
	public static final String I18N_SIGN_9 = "i18n.mityc.xades.sign.9";
	/** Un objeto de Datos privados no admite transformadas. */
	public static final String I18N_SIGN_10 = "i18n.mityc.xades.sign.10";
	/** No se puede continuar porque faltan parámetros de entrada. */
	public static final String I18N_SIGN_11 = "i18n.mityc.xades.sign.11";

	/** Error general validando confianza de certificado: {0}. */
	public static final String I18N_VALIDATE_TRUST_1 = "i18n.mityc.xades.validate.trust.1";
	/** Error general validando confianza de OCSP: {0}. */
	public static final String I18N_VALIDATE_TRUST_2 = "i18n.mityc.xades.validate.trust.2";
	/** Error general validando confianza de CRL: {0}. */
	public static final String I18N_VALIDATE_TRUST_3 = "i18n.mityc.xades.validate.trust.3";
	/** Error general validando confianza de TSA: {0}. */
	public static final String I18N_VALIDATE_TRUST_4 = "i18n.mityc.xades.validate.trust.4"; 
	
	/** No se pudo recuperar el certificado con uri {0}.*/
	public static final String I18N_VALIDATE_1 = "i18n.mityc.xades.validate.1";
	/** No se encontró el certificado o estado de certificado pedido.*/
	public static final String I18N_VALIDATE_2 = "i18n.mityc.xades.validate.2"; 
	/** Se desconoce el tipo de elemento de certificado o estado de certificado pedido: {0}.*/
	public static final String I18N_VALIDATE_3 = "i18n.mityc.xades.validate.3"; 
	/** No se localiza uno de los certificados implicados en la firma ({1}) => ({0}).*/
	public static final String I18N_VALIDATE_4 = "i18n.mityc.xades.validate.4"; 
	/** El campo OCSPResponderID.BY_HASH no tiene forma base64binary: {0}.*/
	public static final String I18N_VALIDATE_5 = "i18n.mityc.xades.validate.5"; 
	/** No se consiguió identificar el tipo de OCSPResponder para el IRecovererElements configurado. */
	public static final String I18N_VALIDATE_6 = "i18n.mityc.xades.validate.6"; 
	/** No se pudo acceder a un reference de la firma: {0}. */
	public static final String I18N_VALIDATE_7 = "i18n.mityc.xades.validate.7";
	/** Nodo DataObjectFormat no apunta a un Reference válido: {0}. */
	public static final String I18N_VALIDATE_8 = "i18n.mityc.xades.validate.8";
	/** Nodo ds:Object tiene URI de encoding mal formada: {0}. */
	public static final String I18N_VALIDATE_9 = "i18n.mityc.xades.validate.9";
	/** No se ha encontrado ninguna cadena de certificados válida en la firma. */
	public static final String I18N_VALIDATE_10 = "i18n.mityc.xades.validate.10";
	/** La forma de un nodo Cert del SigningCertificate no es válida: {0}. */
	public static final String I18N_VALIDATE_11 = "i18n.mityc.xades.validate.11";
	/** El formato del nombre de Issuer de un certificado de SigningCertificate no se ajusta a X500: {0}. */
	public static final String I18N_VALIDATE_12 = "i18n.mityc.xades.validate.12";
	/** Firma inválida. La información sobre el certificado de firma no se ajusta a XAdES. */
	public static final String I18N_VALIDATE_13 = "i18n.mityc.xades.validate.13";
	/** Se aconseja validar el estado del certificado firmante. */
	public static final String I18N_VALIDATE_14 = "i18n.mityc.xades.validate.14";
	/** Uno de los certificados de la cadena fue revocado el {0}. */
	public static final String I18N_VALIDATE_15 = "i18n.mityc.xades.validate.15";
	/** La fecha del sello de tiempo es posterior a la actual. Esto puede deberse a una desincronización entre la fecha local y la fecha del servidor de sellado. Fecha sello: {0} +/- {1} Fecha Sistema: {2}. */
	public static final String I18N_VALIDATE_16 = "i18n.mityc.xades.validate.16";
	/** Esta fecha es posterior a la fecha de firma {0}. La fecha de firma no está garantizada por una Autoridad externa. */
	public static final String I18N_VALIDATE_17 = "i18n.mityc.xades.validate.17";
	/** Se comprueba el estado de revocación del certificado firmante. */
	public static final String I18N_VALIDATE_18 = "i18n.mityc.xades.validate.18";
    /** Uno de los certificados de la cadena fue revocado {0} */
    public static final String I18N_VALIDATE_19 = "i18n.mityc.xades.validate.19";
    /** Uno de los certificados de la cadena tiene estado desconocido {0} */
    public static final String I18N_VALIDATE_20 = "i18n.mityc.xades.validate.20";
    /** No se han podido leer los datos de las respuestas OCSP de la firma **/
    public static final String I18N_VALIDATE_21 = "i18n.mityc.xades.validate.21";
	
	/** Error cargando ficheros de configuración de managers de política: {0}. */
	public static final String I18N_POLICY_1 = "i18n.mityc.xades.policy.1"; 
	/** No se cargó fichero de propiedades {0} debido a error {1}. */
	public static final String I18N_POLICY_2 = "i18n.mityc.xades.policy.2"; 

	/** No se pudo construir identidad de OCSP responder: {0}. */
	public static final String I18N_UTILS_1 = "i18n.mityc.xades.utils.1";
	/** No se pudo construir selectores de DNIe. */
	public static final String I18N_UTILS_2 = "i18n.mityc.xades.utils.2"; 

}
