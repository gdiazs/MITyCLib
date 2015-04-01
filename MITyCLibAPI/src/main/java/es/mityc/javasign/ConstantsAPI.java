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
package es.mityc.javasign;

/**
 * <p>Clase de constantes de la librería base.</p>
 * 
 */
public final class ConstantsAPI {
	
	public static final String PROVIDER_BC_NAME = "BC";

	public static final String PROVIDER_SUN_16_NAME ="SUN version 1.6";

	public static final String PROVIDER_SUN_17_NAME ="SUN version 1.7";
	/**
	 * Constructor.
	 */
	private ConstantsAPI() { }
	
	/** Nombre de la librería. */
	public static final String LIB_NAME = "MITyCLibAPI";	
    
	/** Propiedad de sistema del directorio de usuario. */
	public static final String SYSTEM_PROPERTY_USER_DIR = "user.dir";
	/** Propiedad de sistema del HOME de usuario. */
	public static final String SYSTEM_PROPERTY_USER_HOME = "user.home";
	/** Propiedad de sistema del directorio temporal. */
    public static final String SYSTEM_PROPERTY_TMP_DIR = "java.io.tmpdir";
    /** Propiedad de sistema del path de librerías. */ 
    public static final String SYSTEM_PROPERTY_LIBRARY_PATH = "java.library.path";
    /** Propiedad desistema del path de Java.*/
    public static final String JAVA_HOME = "java.home";
    /** Propiedad del sistema para el separador de directorios en path. */
    public static final String FILE_SEPARATOR = "file.separator";
    
	// Contantes de internacionalización
    
    // Tools
    /** Fichero de propiedades indicado ({0}) no se encuentra debido a {1}.*/
	public static final String I18N_TOOLS_CP_1 = "i18n.mityc.api.tools.cp.1";
    /** Sistema operativo no reconocido.*/
	public static final String I18N_TOOLS_CP_2 = "i18n.mityc.api.tools.cp.2";
    /** Error estableciendo path de librerías nativas de java.*/
	public static final String I18N_TOOLS_CP_3 = "i18n.mityc.api.tools.cp.3";
    /** No se encuentra la clave {0}.*/
	public static final String I18N_TOOLS_CP_4 = "i18n.mityc.api.tools.cp.4";
    /** CRC Adler32 no tiene formato numérico.*/
	public static final String I18N_TOOLS_CP_5 = "i18n.mityc.api.tools.cp.5";
    /** No hay información disponible sobre los ficheros a copiar.*/
	public static final String I18N_TOOLS_CP_6 = "i18n.mityc.api.tools.cp.6";
    /** No se ha encontrado el fichero indicado.*/
	public static final String I18N_TOOLS_CP_7 = "i18n.mityc.api.tools.cp.7";
    /** Error copiando fichero {0} en ruta {1}.*/
	public static final String I18N_TOOLS_CP_8 = "i18n.mityc.api.tools.cp.8";
    /** No se dispone de ningún criterio de integridad.*/
	public static final String I18N_TOOLS_CP_9 = "i18n.mityc.api.tools.cp.9";
    /** Copiando ficheros de {0} en {1}.*/
	public static final String I18N_TOOLS_CP_10 = "i18n.mityc.api.tools.cp.10";
    /** Fichero no existe o alterado. Copiando fichero en ruta {0}.*/
	public static final String I18N_TOOLS_CP_11 = "i18n.mityc.api.tools.cp.11";
    /** Comprobado integridad de fichero {0}.*/
	public static final String I18N_TOOLS_CP_12 = "i18n.mityc.api.tools.cp.12";
    /** CRC obtenido: {0} CRC íntegro: {1}.*/
	public static final String I18N_TOOLS_CP_13 = "i18n.mityc.api.tools.cp.13";
    /** Copiando ficheros a SO {0}.*/
	public static final String I18N_TOOLS_CP_14 = "i18n.mityc.api.tools.cp.14";
    /** Copiando los recursos etiquetados como {0}.*/
	public static final String I18N_TOOLS_CP_15 = "i18n.mityc.api.tools.cp.15";
    /** Actualizando variable LibraryPath con el directorio {0}.*/
	public static final String I18N_TOOLS_CP_16 = "i18n.mityc.api.tools.cp.16";
    /** Hay disponibles {0} recursos con el nombre {1}.*/
	public static final String I18N_TOOLS_CP_17 = "i18n.mityc.api.tools.cp.17";
    /** Length of Base64 encoded input string is not a multiple of 4.*/
	public static final String I18N_TOOLS_CP_18 = "i18n.mityc.api.tools.cp.18";
    /** Illegal character in Base64 encoded data.*/
	public static final String I18N_TOOLS_CP_19 = "i18n.mityc.api.tools.cp.19";
    /** Base64 input not properly padded.*/
	public static final String I18N_TOOLS_CP_20 = "i18n.mityc.api.tools.cp.20";
	/** El directorio {0} no existe. Se creará nuevo. */
	public static final String I18N_TOOLS_CP_21 = "i18n.mityc.api.tools.cp.21";
	/** Copiando el recurso {0} en {1} */
	public static final String I18N_TOOLS_CP_22 = "i18n.mityc.api.tools.cp.22";


	// Trust
	/** Error cargando ficheros de configuración de managers de confianza: {0}.*/
	public static final String I18N_TRUST_1 = "i18n.mityc.api.trust.1";
	/** La clase asociada no se puede instanciar ({0}, {1}).*/
	public static final String I18N_TRUST_2 = "i18n.mityc.api.trust.2";
	/** No hay permisos para instanciar el validador ({0}, {1}).*/
	public static final String I18N_TRUST_3 = "i18n.mityc.api.trust.3";
	/** La clase asociada al valor no se encuentra disponible ({0}, {1}).*/
	public static final String I18N_TRUST_4 = "i18n.mityc.api.trust.4";
	/** La clase asociada no es del tipo validador de confianza esperado ({0}, {1}).*/
	public static final String I18N_TRUST_5 = "i18n.mityc.api.trust.5";
	/** No hay validador de confianza asociado a esa clave: {0}.*/
	public static final String I18N_TRUST_6 = "i18n.mityc.api.trust.6";
	/** El validador de confianza indicado no tiene instanciador ({0}, {1}).*/
	public static final String I18N_TRUST_7 = "i18n.mityc.api.trust.7";
	/** Error intentando instanciar la factoría de validadores de confianza: {0}.*/
	public static final String I18N_TRUST_8 = "i18n.mityc.api.trust.8";
	/** No se cargó fichero de propiedades {0} debido a error {1}.*/
	public static final String I18N_TRUST_9 = "i18n.mityc.api.trust.9";
	/** Nombre por defecto del repositorio externo de certificados de confianza. */
	public static final String TRUSTER_EXTERNAL_CONF_FILE = "truster.properties";

	// Bridge
	/** No hay configuración disponible para instanciar facades de firma.*/ 
	public static final String I18N_BRIDGE_1 = "i18n.mityc.api.bridge.1";
	/** Facade no es una clase instanciable.*/ 
	public static final String I18N_BRIDGE_2 = "i18n.mityc.api.bridge.2";
	/** Clase facade no es accesible en el nivel de seguridad actual.*/ 
	public static final String I18N_BRIDGE_3 = "i18n.mityc.api.bridge.3";
	/** Clase facade {0} indicada no se encuentra.*/ 
	public static final String I18N_BRIDGE_4 = "i18n.mityc.api.bridge.4";
	/** Clase facade indicada no es el tipo esperado.*/ 
	public static final String I18N_BRIDGE_5 = "i18n.mityc.api.bridge.5";
	/** No hay propiedad para indicar clase de facade de servicios de firma.*/ 
	public static final String I18N_BRIDGE_6 = "i18n.mityc.api.bridge.6";
	
    // Certificates
	/** Contraseña de almacén de certificados.*/
	public static final String I18N_CERT_SMR_CARD_TITLE = "i18n.mityc.api.cert.smartcards.GUI.title";
    /** Aceptar.*/
	public static final String I18N_CERT_SMR_CARD_ACCEPT = "i18n.mityc.api.cert.smartcards.GUI.accept";
    /** Cancelar.*/
	public static final String I18N_CERT_SMR_CARD_CANCEL = "i18n.mityc.api.cert.smartcards.GUI.cancel";
    /** Introduzca la contraseña.*/
	public static final String I18N_CERT_SMR_CARD_PIN = "i18n.mityc.api.cert.smartcards.GUI.pin";
	/** Tipo identificador: {0}.*/ 
	public static final String I18N_CERT_1 = "i18n.mityc.api.cert.1";
	/** Nombre X500.*/ 
	public static final String I18N_CERT_2 = "i18n.mityc.api.cert.2";
	/** Hash PublicKey.*/ 
	public static final String I18N_CERT_3 = "i18n.mityc.api.cert.3";
	/** Desconocido.*/ 
	public static final String I18N_CERT_4 = "i18n.mityc.api.cert.4";
	/** (Valor: {0}).*/ 
	public static final String I18N_CERT_5 = "i18n.mityc.api.cert.5";
	
	// Ofuscadores
	/** Error cargando ficheros de configuración de managers de ofuscación: {0}. */
	public static final String I18N_PASS_SECURITY_1 = "i18n.mityc.api.pass.1"; 
	/** No se cargó fichero de propiedades {0} debido a error {1}. */
	public static final String I18N_PASS_SECURITY_2 = "i18n.mityc.api.pass.2"; 
	/** Error en la instanciación del manager de ofuscación: {0}. */
	public static final String I18N_PASS_SECURITY_3 = "i18n.mityc.api.pass.3"; 
	/** No se encontró fichero de configuración en {0}. */
	public static final String I18N_PASS_SECURITY_4 = "i18n.mityc.api.pass.4"; 
	/** No se pudo crear el fichero {0}. */
	public static final String I18N_PASS_SECURITY_5 = "i18n.mityc.api.pass.5"; 
	/** # Salt. */
	public static final String I18N_PASS_SECURITY_6 = "i18n.mityc.api.pass.6"; 
	/** # Iteration. */
	public static final String I18N_PASS_SECURITY_7 = "i18n.mityc.api.pass.7"; 
	/** # Master Key. */
	public static final String I18N_PASS_SECURITY_8 = "i18n.mityc.api.pass.8"; 
	/** No se puede acceder a un generador aleatorio seguro: {0}. */
	public static final String I18N_PASS_SECURITY_9 = "i18n.mityc.api.pass.9"; 
	
	
}
