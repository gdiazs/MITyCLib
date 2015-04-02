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
package es.mityc.javasign.ts;

/**
 * <p>Clase de constantes de la librería de acceso a TSA vía HTTP.</p>
 * 
 */
public final class ConstantsTSA {
	
	/**
	 * Constructor.
	 */
	private ConstantsTSA() { }
	
	/** Nombre de la librería. */
	public static final String LIB_NAME = "MITyCLibTSA";
    
	public static final String FORMATO_FECHA = "dd/MM/yyyy H:mm:ss.SSS";

	public static final String AFIRMA_ID_APLICACION_OID = "1.3.4.6.1.3.4.6";
	
    public static final String MENSAJE_NO_ALGORITMO_HASH = "No se ha encontrado un algoritmo hash válido para el Sello de Tiempo. Se va a utilizar el algoritmo SHA1 por defecto";
    public static final String MENSAJE_NO_DATOS_SELLO_TIEMPO = "No se han especificado los datos sobre los que generar el sello de tiempo";
    public static final String MENSAJE_GENERANDO_SELLO_TIEMPO = "Se va a generar el sello de tiempo ...";
    public static final String MENSAJE_PETICION_TSA_GENERADA = "Petición TSA generada";
    public static final String MENSAJE_ERROR_PETICION_TSA = "Ha ocurrido un error al generar la petición TSA";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_TIMESTAMP_QUERY = "application/timestamp-query";
    public static final String MENSAJE_ERROR_PETICION   = "Error al leer la petición: ";
    public static final String MENSAJE_PETICION_TSA_ENVIADA = "Petición TSA enviada.";
    public static final String MENSAJE_FALLO_EJECUCION_METODO = "Fallo la ejecución del método: ";
    public static final String MENSAJE_RESPUESTA_TSA_OBTENIDA = "Respuesta TSA obtenida.";
    public static final String MENSAJE_RESPUESTA_TSA_VALIDADA_OK = "Respuesta TSA validada OK";
    public static final String MENSAJE_RESPUESTA_NO_VALIDA = "La respuesta no es válida para la petición enviada: ";
    public static final String MENSAJE_RESPUESTA_MAL_FORMADA = "La respuesta está mal formada: ";
    public static final String MENSAJE_SECUENCIA_BYTES_MAL_CODIFICADA = "La secuencia de bytes de respuesta no está codificada en ASN.1: ";
    public static final String MENSAJE_VIOLACION_PROTOCOLO_HTTP = "Violación del protocolo HTTP: ";
    public static final String MENSAJE_ERROR_CONEXION_SERVIDOR_TSA = "Error en la conexión con el servidor TSA: ";
    public static final String MENSAJE_SE_UTILIZA_PROXY = "Se utiliza un servidor Proxy: ";

    public static final String CADENA_VACIA = "";       
    
	// Contantes de internacionalización

	/** Sello de tiempo inválido: se desconoce el algoritmo de huella {0}. */
	public static final String I18N_VALIDATE_1 = "i18n.mityc.ts.validate.1";
	/** Sello de tiempo inválido: el digest de los datos en el sello de tiempo no coincide con el esperado. */
	public static final String I18N_VALIDATE_2 = "i18n.mityc.ts.validate.2";
	/** Sello de tiempo inválido: no se puede comprobar la identidad del firmante del sello. */
	public static final String I18N_VALIDATE_3 = "i18n.mityc.ts.validate.3";
	/** Sello de tiempo inválido: certificado firmante ha expirado. */
	public static final String I18N_VALIDATE_4 = "i18n.mityc.ts.validate.4";
	/** Sello de tiempo inválido: certificado firmante todavía no es válido. */
	public static final String I18N_VALIDATE_5 = "i18n.mityc.ts.validate.5";
	/** Sello de tiempo inválido: certificado firmante no se corresponde con la firma. */
	public static final String I18N_VALIDATE_6 = "i18n.mityc.ts.validate.6";
	/** Sello de tiempo inválido: error comprobando firmante ({0}). */
	public static final String I18N_VALIDATE_7 = "i18n.mityc.ts.validate.7";
	/** No se ha podido extraer el certificado firmante del sello de tiempo: {0}. */
	public static final String I18N_VALIDATE_8 = "i18n.mityc.ts.validate.8";

	/** No se han especificado los datos sobre los que generar el sello de tiempo. */
    public static final String LIBRERIA_TSA_ERROR_1 = "i18n.mityc.ts.error1";
    /** Formato del sello de tiempo desconocido o no válido. */
    public static final String LIBRERIA_TSA_ERROR_2 = "i18n.mityc.ts.error2";
    /** MessageImprint de sello de tiempo desconocido. */
    public static final String LIBRERIA_TSA_ERROR_3 = "i18n.mityc.ts.error3";
    /** No se pudo conectar al servidor TSA: {0}. */
    public static final String LIBRERIA_TSA_ERROR_4 = "i18n.mityc.ts.error4";
    /** Violación del protocolo HTTP: {0}. */
    public static final String LIBRERIA_TSA_ERROR_6 = "i18n.mityc.ts.error6";
    /** La secuencia de bytes de respuesta no esta codificada en ASN.1: {0}. */
    public static final String LIBRERIA_TSA_ERROR_7 = "i18n.mityc.ts.error7";
    /** La respuesta esta mal formada: {0}. */
    public static final String LIBRERIA_TSA_ERROR_8 = "i18n.mityc.ts.error8";
    /** La respuesta no es válida para la petición enviada: {0}. */
    public static final String LIBRERIA_TSA_ERROR_9 = "i18n.mityc.ts.error9";
    /** Ha ocurrido un error al generar la petición TSA: {0}. */
    public static final String LIBRERIA_TSA_ERROR_10 = "i18n.mityc.ts.error10";
    /** Error al leer la petición: {0}. */
    public static final String LIBRERIA_TSA_ERROR_11 = "i18n.mityc.ts.error11";
    /** Fallo la ejecución del método: {0}. */
    public static final String LIBRERIA_TSA_ERROR_12 = "i18n.mityc.ts.error12";

}
