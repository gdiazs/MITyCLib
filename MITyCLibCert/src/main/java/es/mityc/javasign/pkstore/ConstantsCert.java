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
package es.mityc.javasign.pkstore;

/**
 * <p>Clase de constantes de la librería.</p>
 * 
 */
public final class ConstantsCert {

	/** Nombre de la librería. */
	public static final String LIB_NAME = "MITyCLibCert";
	/** Ruta donde se encuentra el fichero de configuración de las librerías nativas de acceso al almacén de iexplorer. */
	public static final String CP_IE_PROPERTIES = "libs/iexplorer/MITyCLibCertJNI_iexplorer.properties";
	/** Ruta donde se encuentra el fichero de configuración de las librerías nativas de acceso al almacén de mozilla. */
	public static final String CP_MZ_PROPERTIES = "libs/mozilla/MITyCLibCertJNI_mozilla.properties";
	/** Ruta donde se encuentra el fichero de configuración de las librerías nativas de acceso al almacén de SunMSCAPI MITyC. */
	public static final String CP_SUNMSCAPIMITYC_PROPERTIES = "libs/sunmscapimityc/MITyCLibCertJNI_sunmscapimityc.properties";
	
	/** Clave para recuperar el nombre del almacén de certificados de la configuración. */
	public static final String KS_NAME_KEY = "KeyStoreName";
	/**  Constantes del sistema.- Ruta al directorio de usuario. */
	public static final String USER_HOME = "user.home";
	/** Nombre del directorio destino para el almacén. */
	public static final String DIR_NAME = ".MITyC";
    
	// Constantes SunMSCAPI_MITyC
	/** Prefijo relacionado con el almacén de certificados de windows del fichero de librerías. */
    public static final String CP_SUNMSCAPIMITYC = "explorer";
	
	// Constantes de IExplorer
	/** Prefijo relacionado con el almacén de certificados de windows del fichero de librerías. */
    public static final String CP_EXPLORER = "explorer";
    /** Nombre de la librería JNI de acceso a CSP. */
    public static final String CSP_JNI_IE = "DLLFirmaVC";
    /** Nombre del almacén personal de certificados en windows. */
    public static final String MY_STORE = "MY";
    
	// Contantes de internacionalización IExplorer
    /** Error cargando JNI a CSP IExplorer: {0}.*/
	public static final String I18N_CERT_IE_1 = "i18n.mityc.cert.ie.1";
    /** Método no implementado.*/
	public static final String I18N_CERT_IE_2 = "i18n.mityc.cert.ie.2";
    /** Este motor de firma no implementa parámetros.*/
	public static final String I18N_CERT_IE_3 = "i18n.mityc.cert.ie.3";
    /** Este motor de firma no implementa validación.*/
	public static final String I18N_CERT_IE_4 = "i18n.mityc.cert.ie.4";
    /** No se dispone de clave para realizar la firma.*/
	public static final String I18N_CERT_IE_5 = "i18n.mityc.cert.ie.5";
    /** No se dispone de datos para firmar.*/
	public static final String I18N_CERT_IE_6 = "i18n.mityc.cert.ie.6";
    /** Error calculando firma: {0}.*/
	public static final String I18N_CERT_IE_7 = "i18n.mityc.cert.ie.7";

	// Contantes de internacionalización de MSCAPI
	/** Error accediendo KeyStore: {0}.*/
	public static final String I18N_CERT_MSCAPI_1 = "i18n.mityc.cert.mscapi.1";
	/** Problema con el algoritmo de recuperación de la clave: {0}.*/
	public static final String I18N_CERT_MSCAPI_2 = "i18n.mityc.cert.mscapi.2"; 
	/** Error al cargar el certificado: {0}.*/
	public static final String I18N_CERT_MSCAPI_3 = "i18n.mityc.cert.mscapi.3"; 
	/** Error de E/S al cargar el certificado: {0}.*/
	public static final String I18N_CERT_MSCAPI_4 = "i18n.mityc.cert.mscapi.4"; 
	/** Error al introducir el proveedor: {0}.*/
	public static final String I18N_CERT_MSCAPI_5 = "i18n.mityc.cert.mscapi.5"; 
	/** Fallo de contraseña.*/
	public static final String I18N_CERT_MSCAPI_6 = "i18n.mityc.cert.mscapi.6"; 
	/** No hay proveedor SunMSCAPI disponible.*/
	public static final String I18N_CERT_MSCAPI_7 = "i18n.mityc.cert.mscapi.7"; 
    /** No hay proveedor SunMSCAPI MITyC disponible: {0}.*/
    public static final String I18N_CERT_MSCAPI_8 = "i18n.mityc.cert.mscapi.8"; 
    /** Usando pasarela Sun-MITyC para almacén de windows.*/
    public static final String I18N_CERT_MSCAPI_9 = "i18n.mityc.cert.mscapi.9"; 
    /** Usando pasarela Sun para almacén de windows.*/
    public static final String I18N_CERT_MSCAPI_10 = "i18n.mityc.cert.mscapi.10"; 

    // Contantes de internacionalización de MSCAPI MITYC
    /** Error copiando la librería nativa. */
    public static final String I18N_CERT_MSCAPIMITYC_1 = "i18n.mityc.cert.mscapimityc.1"; 

	// Constantes de Mozilla
	/** Prefijo relacionado con los recursos asociados al almacén de certificados de mozilla en una aplicación cliente. */
    public static final String CP_MOZILLA_CLIENTE = "mozilla.cliente";
    /** Prefijo relacionado con los recursos asociados al almacén de certificados de mozilla en un applet. */
    public static final String CP_MOZILLA_JSS_ONLY = "mozilla.jss";
    /** Prefijo relacionado con los recursos asociados al almacén de certificados de mozilla vía PKCS11-NSS. */
    public static final String CP_MOZILLA_PKCS11_ONLY = "mozilla.pkcs11";

    // Contantes de internacionalización Mozilla
    /** Error cargando JNI a JSS: {0}.*/
	public static final String I18N_CERT_MOZILLA_1 = "i18n.mityc.cert.mozilla.1"; //
    /** Error inicializando JSS: {0}.*/
	public static final String I18N_CERT_MOZILLA_2 = "i18n.mityc.cert.mozilla.2"; // 
    /** Error obteniendo ventana de Pasword para mozilla: {0}.*/
	public static final String I18N_CERT_MOZILLA_3 = "i18n.mityc.cert.mozilla.3"; // 
    /** Error al convertir certificado de mozilla: {0}.*/
	public static final String I18N_CERT_MOZILLA_4 = "i18n.mityc.cert.mozilla.4"; // 
    /** No se puede acceder a la clave privada del certificado indicado.*/
	public static final String I18N_CERT_MOZILLA_5 = "i18n.mityc.cert.mozilla.5"; // 
    /** Error al introducir el PIN.*/
	public static final String I18N_CERT_MOZILLA_6 = "i18n.mityc.cert.mozilla.6"; // 
    /** Error al acceder a un token de mozilla: {0}.*/
	public static final String I18N_CERT_MOZILLA_7 = "i18n.mityc.cert.mozilla.7"; // 
    /** PIN.*/
	public static final String I18N_CERT_MOZILLA_8 = "i18n.mityc.cert.mozilla.8"; // 
    /** No se puede acceder al almacén de certificados de Mozilla. Compruebe su configuración.*/
	public static final String I18N_CERT_MOZILLA_9 = "i18n.mityc.cert.mozilla.9"; // 
    /** Contraseña de almacén de certificados.*/
	public static final String I18N_CERT_SMR_CARD_TITLE = "i18n.mityc.cert.smartcards.GUI.title";
    /** Aceptar.*/
	public static final String I18N_CERT_SMR_CARD_ACCEPT = "i18n.mityc.cert.smartcards.GUI.accept";
    /** Cancelar.*/
	public static final String I18N_CERT_SMR_CARD_CANCEL = "i18n.mityc.cert.smartcards.GUI.cancel";
    /** Introduzca la contraseña para.*/
	public static final String I18N_CERT_SMR_CARD_PIN = "i18n.mityc.cert.smartcards.GUI.pin";
    /** No se pudo crear la ventana de petición de PIN.*/
	public static final String I18N_CERT_SMR_CARD_1 = "i18n.mityc.cert.smartcards.GUI.1";
	
    // Contantes de internacionalización Mac OS X
    /** Error accediendo a almacén de Mac Os X: {0}.*/
	public static final String I18N_CERT_MACOSX_1 = "i18n.mityc.cert.macosx.1";

    // Contantes de internacionalización DNIe JCA
    /** Error accediendo a almacén de DNIe por JCA: {0}.*/
    public static final String I18N_CERT_DNIE_1 = "i18n.mityc.cert.dnie.1";
    /** No se encuentra insertado el DNI.*/
    public static final String I18N_CERT_DNIE_2 = "i18n.mityc.cert.dnie.2";
    /** El DNI se encuentra bloqueado.*/
    public static final String I18N_CERT_DNIE_3 = "i18n.mityc.cert.dnie.3";
    /** La tarjeta introducida no es válida.*/
    public static final String I18N_CERT_DNIE_4 = "i18n.mityc.cert.dnie.4";
    /** No se ha detectado ningún lector de tarjetas.*/
    public static final String I18N_CERT_DNIE_5 = "i18n.mityc.cert.dnie.5";
    /** No se ha podido leer correctamente el DNI.*/
    public static final String I18N_CERT_DNIE_6 = "i18n.mityc.cert.dnie.6";
    /** Error accediendo a la tarjeta.*/
    public static final String I18N_CERT_DNIE_7 = "i18n.mityc.cert.dnie.7";

	// Contantes de internacionalización KeyStore
    /** Error accediendo KeyStore {0}: {1}.*/
	public static final String I18N_CERT_KS_1 = "i18n.mityc.cert.ks.1";
    /** Problema con el algoritmo de recuperación de la clave: {0}.*/
	public static final String I18N_CERT_KS_2 = "i18n.mityc.cert.ks.2";
	/** Este manejador sólo gestiona peticiones de contraseñas.*/
	public static final String I18N_CERT_KS_3 = "i18n.mityc.cert.ks.3";
	/** No se ha podido recuperar la clave privada: {0}.*/
	public static final String I18N_CERT_KS_4 = "i18n.mityc.cert.ks.4";
	/** No se ha encontrado ninguna clave privada asociada al certificado indicado.*/
	public static final String I18N_CERT_KS_5 = "i18n.mityc.cert.ks.5";
	/** No se ha encontrado el certificado indicado en el almacén.*/
	public static final String I18N_CERT_KS_6 = "i18n.mityc.cert.ks.6";
	
    // Contantes de internacionalización PKCS11
	/** Error recuperando el listado de slots disponibles: {0}.*/
	public static final String I18N_CERT_PKCS11_1 = "i18n.mityc.cert.p11.1";
	/** No se pudo asociar el proveedor {0} con el slot {1}.*/
	public static final String I18N_CERT_PKCS11_2 = "i18n.mityc.cert.p11.2";
	/** Este manejador sólo gestiona peticiones de contraseñas.*/
	public static final String I18N_CERT_PKCS11_3 = "i18n.mityc.cert.p11.3";
	/** El certificado indicado no pertenece a este almacén.*/
	public static final String I18N_CERT_PKCS11_4 = "i18n.mityc.cert.p11.4";
	/** No se ha podido acceder a la clave privada del certificado indicado.*/
	public static final String I18N_CERT_PKCS11_5 = "i18n.mityc.cert.p11.5";
	/** Intento de acceso a función no disponible.*/
	public static final String I18N_CERT_PKCS11_6 = "i18n.mityc.cert.p11.6";
	/** Provider proxy para el acceso a providers específicos de módulos PKCS#11.*/
	public static final String I18N_CERT_PKCS11_7 = "i18n.mityc.cert.p11.7";
	/** Incluido nuevo provider ({0}) en slot ID {1}.*/
	public static final String I18N_CERT_PKCS11_8 = "i18n.mityc.cert.p11.8";
	/** Configurado acceso para módulos PKCS#11 {0}.*/
	public static final String I18N_CERT_PKCS11_9 = "i18n.mityc.cert.p11.9";
	/** Actualizando módulo PKCS#11 {0}.*/
	public static final String I18N_CERT_PKCS11_10 = "i18n.mityc.cert.p11.10";
	/** Disponibles {0} slots.*/
	public static final String I18N_CERT_PKCS11_11 = "i18n.mityc.cert.p11.11";
	/** {0}: {1} (IDs: {2}).*/
	public static final String I18N_CERT_PKCS11_12 = "i18n.mityc.cert.p11.12";
	/** ninguno.*/
	public static final String I18N_CERT_PKCS11_13 = "i18n.mityc.cert.p11.13";
	/** Slots ocupados.*/
	public static final String I18N_CERT_PKCS11_14 = "i18n.mityc.cert.p11.14";
	/** Slots ocupados que reconoce {0}.*/
	public static final String I18N_CERT_PKCS11_15 = "i18n.mityc.cert.p11.15";
	/** No se encuentra el proveedor de SUN para el acceso a módulos PKCS#11: {0}.*/
	public static final String I18N_CERT_PKCS11_16 = "i18n.mityc.cert.p11.16";
	/** Clase SunPKCS11 no se encuentra.*/
	public static final String I18N_CERT_PKCS11_17 = "i18n.mityc.cert.p11.17";
	
	/** Error cargando los certificados de firma. */
	public static final String I18N_CERT_MITYC_1 = "i18n.mityc.cert.mityc.1";
	/** Error.- No se pudo construir la cadena de confianza. */
	public static final String I18N_CERT_MITYC_2 = "i18n.mityc.cert.mityc.2";
	/** Error.- No se dispone de un proveedor criptográfico. */
	public static final String I18N_CERT_MITYC_3 = "i18n.mityc.cert.mityc.3";
	/** Se va a utilizar la clave privada asociada al certificado llamado {0}\n¿Desea continuar?. */
	public static final String I18N_CERT_MITYC_4 = "i18n.mityc.cert.mityc.4";
	/** Acceso a clave privada. */
	public static final String I18N_CERT_MITYC_5 = "i18n.mityc.cert.mityc.5";
	/** El certificado no tiene clave privada asociada. */
	public static final String I18N_CERT_MITYC_6 = "i18n.mityc.cert.mityc.6";
	/** No se pudo recuperar la clave privada. No se reconoce el algoritmo. */
	public static final String I18N_CERT_MITYC_7 = "i18n.mityc.cert.mityc.7";
	/** La clave privada no es extraíble. */
	public static final String I18N_CERT_MITYC_8 = "i18n.mityc.cert.mityc.8";
	/** Error cargando los certificados de autenticación. */
	public static final String I18N_CERT_MITYC_9 = "i18n.mityc.cert.mityc.9";
	/** El almacén no está inicializado. */
	public static final String I18N_CERT_MITYC_10 = "i18n.mityc.cert.mityc.10";
	/** Imposible inicializar: No se encuentra la ruta al almacén de certificados. */
	public static final String I18N_CERT_MITYC_11 = "i18n.mityc.cert.mityc.11";
	/** el almacén MITyC. */
	public static final String I18N_CERT_MITYC_12 = "i18n.mityc.cert.mityc.12";
	/** El almacén no existe. */
	public static final String I18N_CERT_MITYC_13 = "i18n.mityc.cert.mityc.13";
	/** No se encuentra disponible la configuración específica para esta pasarela. Recuerde crear y configurar el fichero MITyC_KS.properties. */
	public static final String I18N_CERT_MITYC_14 = "i18n.mityc.cert.mityc.14";
	/** Faltan parámetros. */
	public static final String I18N_CERT_MITYC_15 = "i18n.mityc.cert.mityc.15";
	/** El certificado no existe en el almacén. */
	public static final String I18N_CERT_MITYC_16 = "i18n.mityc.cert.mityc.16";
	/** Hubo un problema al salvar el KeyStore. */
	public static final String I18N_CERT_MITYC_17 = "i18n.mityc.cert.mityc.17";
	/** Contexto de clave. */
	public static final String I18N_CERT_MITYC_18 = "i18n.mityc.cert.mityc.18";
	/** Protegido con contraseña. */
	public static final String I18N_CERT_MITYC_19 = "i18n.mityc.cert.mityc.19";
	/** Contraseña. */
	public static final String I18N_CERT_MITYC_20 = "i18n.mityc.cert.mityc.20";
	/** Sólo pedir la primera vez. */
	public static final String I18N_CERT_MITYC_21 = "i18n.mityc.cert.mityc.21";
	/** No protegido con contraseña. */
	public static final String I18N_CERT_MITYC_22 = "i18n.mityc.cert.mityc.22";
	/** Alertar en su uso. */
	public static final String I18N_CERT_MITYC_23 = "i18n.mityc.cert.mityc.23";
	/** Clave privada. */
	public static final String I18N_CERT_MITYC_24 = "i18n.mityc.cert.mityc.24";
	/** Propietario: {0}. */
	public static final String I18N_CERT_MITYC_25 = "i18n.mityc.cert.mityc.25";
	/** Nombre completo: {0}. */
	public static final String I18N_CERT_MITYC_26 = "i18n.mityc.cert.mityc.26";
	/** Emisor: {0}. */
	public static final String I18N_CERT_MITYC_27 = "i18n.mityc.cert.mityc.27";
	/** Validez: {0}. */
	public static final String I18N_CERT_MITYC_28 = "i18n.mityc.cert.mityc.28";
	/** Nº de serie: {0}. */
	public static final String I18N_CERT_MITYC_29 = "i18n.mityc.cert.mityc.29";
	/** Usos: {0}. */
	public static final String I18N_CERT_MITYC_30 = "i18n.mityc.cert.mityc.30";
	/** Algoritmo de firma: {0}. */
	public static final String I18N_CERT_MITYC_31 = "i18n.mityc.cert.mityc.31";
	/**  Certificado aún no válido. */
	public static final String I18N_CERT_MITYC_32 = "i18n.mityc.cert.mityc.32";
	/**  Certificado caducado. */
	public static final String I18N_CERT_MITYC_33 = "i18n.mityc.cert.mityc.33";
	/** Desde {0} hasta {1}. */
	public static final String I18N_CERT_MITYC_34 = "i18n.mityc.cert.mityc.34";
	/** Firma digital. */
	public static final String I18N_CERT_MITYC_35 = "i18n.mityc.cert.mityc.35";
	/** No repudio. */
	public static final String I18N_CERT_MITYC_36 = "i18n.mityc.cert.mityc.36";
	/** Cifrado de claves. */
	public static final String I18N_CERT_MITYC_37 = "i18n.mityc.cert.mityc.37";
	/** Cifrado de datos. */
	public static final String I18N_CERT_MITYC_38 = "i18n.mityc.cert.mityc.38";
	/** Acuerdo de claves. */
	public static final String I18N_CERT_MITYC_39 = "i18n.mityc.cert.mityc.39";
	/** Firma de certificados. */
	public static final String I18N_CERT_MITYC_40 = "i18n.mityc.cert.mityc.40";
	/** Firma de CRL. */
	public static final String I18N_CERT_MITYC_41 = "i18n.mityc.cert.mityc.41";
	/** Sólo cifrado. */
	public static final String I18N_CERT_MITYC_42 = "i18n.mityc.cert.mityc.42";
	/** Sólo firma. */
	public static final String I18N_CERT_MITYC_43 = "i18n.mityc.cert.mityc.43";
	/** No definido. */
	public static final String I18N_CERT_MITYC_44 = "i18n.mityc.cert.mityc.44";
	/** Sin datos. */
	public static final String I18N_CERT_MITYC_45 = "i18n.mityc.cert.mityc.45";
	/** Certificados. */
	public static final String I18N_CERT_MITYC_46 = "i18n.mityc.cert.mityc.46";
	/** Emitido para. */
	public static final String I18N_CERT_MITYC_47 = "i18n.mityc.cert.mityc.47";
	/** Emitido por. */
	public static final String I18N_CERT_MITYC_48 = "i18n.mityc.cert.mityc.48";
	/** Fecha de caducidad. */
	public static final String I18N_CERT_MITYC_49 = "i18n.mityc.cert.mityc.49";
	/** Certificado. */
	public static final String I18N_CERT_MITYC_50 = "i18n.mityc.cert.mityc.50";
	/** Datos del certificado. */
	public static final String I18N_CERT_MITYC_51 = "i18n.mityc.cert.mityc.51";
	/** Exportar. */
	public static final String I18N_CERT_MITYC_52 = "i18n.mityc.cert.mityc.52";
	/** Exportar certificado. */
	public static final String I18N_CERT_MITYC_53 = "i18n.mityc.cert.mityc.53";
	/** No se pudo salvar. No se encuentra el destino. */
	public static final String I18N_CERT_MITYC_54 = "i18n.mityc.cert.mityc.54";
	/** No se pudo salvar. Hubo un error de escritura. */
	public static final String I18N_CERT_MITYC_55 = "i18n.mityc.cert.mityc.55";
	/** No se pudo salvar. Error de codificación del certificado. */
	public static final String I18N_CERT_MITYC_56 = "i18n.mityc.cert.mityc.56";
	/** Almacén de certificados MITyC. */
	public static final String I18N_CERT_MITYC_57 = "i18n.mityc.cert.mityc.57";
	/** Configuración a cargar. */
	public static final String I18N_CERT_MITYC_58 = "i18n.mityc.cert.mityc.58";
	/** No se pudo inicializar el almacén. Compruebe su configuración. */
	public static final String I18N_CERT_MITYC_59 = "i18n.mityc.cert.mityc.59";
	/** Archivo. */
	public static final String I18N_CERT_MITYC_60 = "i18n.mityc.cert.mityc.60";
	/** Cargar configuración. */
	public static final String I18N_CERT_MITYC_61 = "i18n.mityc.cert.mityc.61";
	/** Salir. */
	public static final String I18N_CERT_MITYC_62 = "i18n.mityc.cert.mityc.62";
	/** Ayuda. */
	public static final String I18N_CERT_MITYC_63 = "i18n.mityc.cert.mityc.63";
	/** Mostrar. */
	public static final String I18N_CERT_MITYC_64 = "i18n.mityc.cert.mityc.64";
	/** Otro botón. */
	public static final String I18N_CERT_MITYC_65 = "i18n.mityc.cert.mityc.65";
	/** Error construyendo ventana de certificados: {0}. */
	public static final String I18N_CERT_MITYC_66 = "i18n.mityc.cert.mityc.66";
	/** Certificados propios. */
	public static final String I18N_CERT_MITYC_67 = "i18n.mityc.cert.mityc.67";
	/** Autoridades de confianza. */
	public static final String I18N_CERT_MITYC_68 = "i18n.mityc.cert.mityc.68";
	/** Actualizar. */
	public static final String I18N_CERT_MITYC_69 = "i18n.mityc.cert.mityc.69";
	/** Borrar. */
	public static final String I18N_CERT_MITYC_70 = "i18n.mityc.cert.mityc.70";
	/** Añadir. */
	public static final String I18N_CERT_MITYC_71 = "i18n.mityc.cert.mityc.71";
	/** Almacén de certificados. */
	public static final String I18N_CERT_MITYC_72 = "i18n.mityc.cert.mityc.72";
	/** Añadir certificado. */
	public static final String I18N_CERT_MITYC_73 = "i18n.mityc.cert.mityc.73";
	/** No se pudo añadir el certificado. */
	public static final String I18N_CERT_MITYC_74 = "i18n.mityc.cert.mityc.74";
	/** El fichero indicado no existe o no se encuentra. */
	public static final String I18N_CERT_MITYC_75 = "i18n.mityc.cert.mityc.75";
	/** La contraseña no es válida. No se pudo acceder al contenedor P12. */
	public static final String I18N_CERT_MITYC_76 = "i18n.mityc.cert.mityc.76";
	/** Error. */
	public static final String I18N_CERT_MITYC_77 = "i18n.mityc.cert.mityc.77";
	/** El contenedor P12 está vacío. */
	public static final String I18N_CERT_MITYC_78 = "i18n.mityc.cert.mityc.78";
	/** La contraseña no es válida. No se pudo acceder a la clave privada. */
	public static final String I18N_CERT_MITYC_79 = "i18n.mityc.cert.mityc.79";
	/** obtener la clave privada. */
	public static final String I18N_CERT_MITYC_80 = "i18n.mityc.cert.mityc.80";
	/** Cancelado por el usuario. */
	public static final String I18N_CERT_MITYC_81 = "i18n.mityc.cert.mityc.81";
	/** No se puede borrar el certificado. */
	public static final String I18N_CERT_MITYC_82 = "i18n.mityc.cert.mityc.82";
	/** Se va a borrar el certificado llamado {0}\n¿Desea continuar?. */
	public static final String I18N_CERT_MITYC_83 = "i18n.mityc.cert.mityc.83";
	/** Preferencias. */
	public static final String I18N_CERT_MITYC_84 = "i18n.mityc.cert.mityc.84";
	/** No se pudo acceder al almacén. Compruebe su contraseña. */
	public static final String I18N_CERT_MITYC_85 = "i18n.mityc.cert.mityc.85";
	/** Introduzca la nueva contraseña de acceso\n(Deje el campo vacío para que no se pida contraseña al acceder). */
	public static final String I18N_CERT_MITYC_86 = "i18n.mityc.cert.mityc.86";
	/** Contraseña antigua. */
	public static final String I18N_CERT_MITYC_87 = "i18n.mityc.cert.mityc.87";
	/** Contraseña nueva. */
	public static final String I18N_CERT_MITYC_88 = "i18n.mityc.cert.mityc.88";
	/** Sin contraseña. */
	public static final String I18N_CERT_MITYC_89 = "i18n.mityc.cert.mityc.89";
	/** Preferencias. */
	public static final String I18N_CERT_MITYC_90 = "i18n.mityc.cert.mityc.90";
	/** No se pudo cambiar la contraseña.\nCompruebe la contraseña antigua. */
	public static final String I18N_CERT_MITYC_91 = "i18n.mityc.cert.mityc.91";
	/** La librería indicada no se encuentra: {0}. */
	public static final String I18N_CERT_MITYC_92 = "i18n.mityc.cert.mityc.92";
	/** El certificado no es actualizable. */
	public static final String I18N_CERT_MITYC_93 = "i18n.mityc.cert.mityc.93";
	/** Nombre. */
	public static final String I18N_CERT_MITYC_94 = "i18n.mityc.cert.mityc.94";
	/** Ruta al driver. */
	public static final String I18N_CERT_MITYC_95 = "i18n.mityc.cert.mityc.95";
	/** No se puede salvar la configuración. */
	public static final String I18N_CERT_MITYC_96 = "i18n.mityc.cert.mityc.96";
	/** Ruta al driver PKCS#11. */
	public static final String I18N_CERT_MITYC_97 = "i18n.mityc.cert.mityc.97";
	/** Un certificado para firma requiere una clave privada asociada. */
	public static final String I18N_CERT_MITYC_98 = "i18n.mityc.cert.mityc.98";
	
	/**
	 * <p>Constructor.</p>
	 */
	private ConstantsCert() {
	}
}
