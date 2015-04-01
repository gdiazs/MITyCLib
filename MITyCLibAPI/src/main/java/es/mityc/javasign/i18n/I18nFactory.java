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
package es.mityc.javasign.i18n;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>Factoría para la obtención de los managers de mensajes locales.</p>
 * 
 * <p>En primer lugar busca el fichero de configuración i18n/i18n.properties que haya por encima en el classpath para la
 * configuración del comportamiento de la factoría de internacionalización. Este fichero ha de cumplir el formato:
 * <pre>
 * # Clase factoría encargada de generar los manager de internacionalización (si
 * # no se indica factory se utilizará el de por defecto).
 * i18n.factory.class=
 * 
 * # Si se deja la factoría por defecto:
 * # 	Clase manager que gestionará las entradas de idioma (debe implementar el
 * #    interfaz II18nManager)
 * i18n.manager.class=
 * # 	Locale que se utilizará por defecto cuando no se indique ninguno
 * # 	(opcional, si no se indica se utilizará el locale por defecto del sistema)
 * i18n.locale.default=
 * </pre>
 * La clase indicada en la propiedad <code>i18n.factory.class</code> debe tener un método newInstance() estático que debe devolver un
 * objeto de tipo II18nFactory. Este método será el consultado para obtener la nueva factoría. 
 * </p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class I18nFactory {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(I18nFactory.class);
	
	/** Fichero de propiedades que tiene la configuración de los internacionalizadores. */
	private static final String PATH_RES_I18N_PROPS = "i18n/i18n.properties";
	/** Clase encargada de generar la factoría de managers de internacionalización. */
	private static final String CLASS_FACTORY = "i18n.factory.class";
	/** Clase encargada de internacionalizar. */
	private static final String CLASS_MANAGER = "i18n.manager.class";
	/** Locale por defecto. */
	private static final String LOCALE_DEFAULT = "i18n.locale.default";
	/** Nombre del método que devuelve una nueva instancia. */
	private static final String METHOD_NEW_INSTANCE = "newInstance";

	/** Separador de elementos en un locale. */
	private static final String STRING_SPACE = "_";
	/** Cadena vacía. */
	private static final String STRING_EMPTY = "";
	/** Local no reconocido. */
	private static final String WARN_UNKNOWN_LOCALE = "Locale no reconocido";
	/** No se ha configurado un Locale específico. */
	private static final String NOT_CONFIGURATED_LOCALE = "No se ha configurado un Locale específico";
	/** No se ha configurado ninguna factoría propia para la internacionalización. */
	private static final String ERROR_CONFIGURATION_FACTORY = "No se ha configurado ninguna factoría propia para la internacionalización";
	/** Clase indicada no tiene constructor nulo: {0}. */
	private static final String ERROR_IMPLEMENTED_CLASS = "Clase indicada no tiene constructor nulo: {0}";
	/** Clase indicada no es del tipo II18nFactory: {0}. */
	private static final String ERROR_CASTING_FACTORY = "Clase indicada no es del tipo II18nFactory: {0}";
	/** Clase indicada no existe: {0}. */
	private static final String ERROR_NOT_AVALAIBLE_CLASS = "Clase indicada no existe: {0}";
	/** Clase indicada no es accesible: {0}. */
	private static final String ERROR_ACCESING_CLASS = "Clase indicada no es accesible: {0}";
	/** Error creando instancia de factoría de internacionalización: {0}. */
	private static final String ERROR_INSTANTIATION_FACTORY = "Error creando instancia de factoría de internacionalización: {0}";
	/** No hay manager de internacionalización configurado. */
	private static final String NOT_I18N_MANAGER_CONFIGURATED = "No hay manager de internacionalización configurado";
	/** No hay fichero de configuración específico. */
	private static final String NOTAVALAIBLE_FILE_I18N_PROPS = "No hay fichero de configuración específico";
	/** Error en la inicialización del manager con el diccionario {0}. */
	private static final String ERROR_INIT_MANAGER = "Error en la inicialización del manager con el diccionario {0}";
	/** Clase indicada no es del tipo II18nManager: {0}. */
	private static final String ERROR_CASTING_MANAGER = "Clase indicada no es del tipo II18nManager: {0}";
	/** Error creando instancia de manager de internacionalización: {0}. */
	private static final String ERROR_INSTANTIATION_MANAGER = "Error creando instancia de manager de internacionalización: {0}";


	/** Locale configurado por defecto. */
	private static Locale locale = null;
	/** Factoría encargada de instanciar los managers de internacionalización. */
	private static II18nFactory factory = null;
	/** Contructor del manager de internacionalización. */
	private static Constructor< ? extends II18nManager> classManager = null;
	/** Caché interna de managers de internacionalización. */
	private static HashMap<String, ManagerCached> cache = new HashMap<String, ManagerCached>();
	
	/**
	 * Carga la configuración básica de la factoría.
	 */
	static {
		// Busca el fichero i18n, si no lo encuentra recoge el fichero local.
		Properties rb = null;
		try {
			InputStream is = getClassLoader().getResourceAsStream(PATH_RES_I18N_PROPS);
			if (is != null) {
				rb = new Properties();
				rb.load(is);
			} else {
				LOG.trace(NOTAVALAIBLE_FILE_I18N_PROPS);
			}
		} catch (IOException ex) {
			LOG.trace(NOTAVALAIBLE_FILE_I18N_PROPS);
		}
		loadFactory(rb);
		// Si no hay factoría propia carga el resto de valores
		if ((factory == null) && (rb != null)) {
			// Carga el nombre de la clase del manager de internacionalización
			String classnameManager = rb.getProperty(CLASS_MANAGER);
			if (classnameManager != null) {
				if (STRING_EMPTY.equals(classnameManager.trim())) {
					classnameManager = null;
				} else {
					loadManager(classnameManager);
				}
			} 
			if (classManager == null) {
				LOG.trace(NOT_I18N_MANAGER_CONFIGURATED);
			}
			// Carga el nombre de la localización
			loadLocale(rb);
		}
	}
	
	/** 
	 * <p>Constructor.</p>
	 */
	protected I18nFactory() {
	}
	
	/**
	 * <p>Recupera el ClassLoader de contexto si está disponible.</p>
	 * <p>Si no está disponible el de contexto devuelve el propio de la clase.</p>
	 * @return ClassLoader
	 */
	private static ClassLoader getClassLoader() {
		try {
			ClassLoader cl = AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
			    public ClassLoader run() {
					ClassLoader classLoader = null;
					try {
					    classLoader = Thread.currentThread().getContextClassLoader();
					} catch (SecurityException ex) {
					}
					return classLoader;
			    }
			});
			if (cl != null) {
				return cl;
			}
		} catch (Exception ex) {
		}
		return I18nFactory.class.getClassLoader();
	}

	
	/**
	 * <p>Carga la factoría de managers de internacionalización.</p>
	 * 
	 * @param rb Properties que contiene las propiedades de configuración
	 */
	private static void loadFactory(final Properties rb) {
		if (rb != null) {
			String classname = rb.getProperty(CLASS_FACTORY);
			if ((classname != null) && (!STRING_EMPTY.equals(classname.trim()))) {
				try {
					ClassLoader cl = getClassLoader();
					Class< ? > classFactory = null;
					if (cl != null) {
						classFactory = cl.loadClass(classname);
					} else {
						classFactory = Class.forName(classname);
					}
					if (classFactory != null) {
						Method method = classFactory.getDeclaredMethod(METHOD_NEW_INSTANCE);
						Class< ? > returnType = method.getReturnType();
						if ((returnType != null) && (returnType.isAssignableFrom(II18nFactory.class))) {
							factory = (II18nFactory) method.invoke(null);
						}
					}
				} catch (IllegalAccessException ex) {
					LOG.error(getFormatedMessage(ERROR_ACCESING_CLASS, classname), ex);
				} catch (ClassNotFoundException ex) {
					LOG.error(getFormatedMessage(ERROR_NOT_AVALAIBLE_CLASS, classname), ex);
				} catch (ClassCastException ex) {
					LOG.error(getFormatedMessage(ERROR_CASTING_FACTORY, classname), ex);
				} catch (SecurityException ex) {
					LOG.error(getFormatedMessage(ERROR_ACCESING_CLASS, classname), ex);
				} catch (NoSuchMethodException ex) {
					LOG.error(getFormatedMessage(ERROR_IMPLEMENTED_CLASS, classname), ex);
				} catch (IllegalArgumentException ex) {
					LOG.error(getFormatedMessage(ERROR_IMPLEMENTED_CLASS, classname), ex);
				} catch (InvocationTargetException ex) {
					LOG.error(getFormatedMessage(ERROR_INSTANTIATION_FACTORY, classname), ex);
				}
			} else {
				LOG.trace(ERROR_CONFIGURATION_FACTORY);
			}
		}
	}
	
	/**
	 * <p>Carga la clase encargada de la internacionalización.</p>
	 * @param classname Nombre de la clase
	 */
	private static void loadManager(final String classname) {
		try {
			ClassLoader cl = getClassLoader();
			Class< ? > classTemp = null;
			if (cl != null) {
				classTemp = cl.loadClass(classname);
			} else {
				classTemp = Class.forName(classname);
			}
			if (classTemp != null) {
				Class< ? extends II18nManager> classI18n = classTemp.asSubclass(II18nManager.class);
				classManager = classI18n.getConstructor((Class[]) null);
			}
		} catch (ClassNotFoundException ex) {
			LOG.error(getFormatedMessage(ERROR_NOT_AVALAIBLE_CLASS, classname), ex);
		} catch (ClassCastException ex) {
			LOG.error(getFormatedMessage(ERROR_CASTING_FACTORY, classname), ex);
		} catch (SecurityException ex) {
			LOG.error(getFormatedMessage(ERROR_ACCESING_CLASS, classname), ex);
		} catch (NoSuchMethodException ex) {
			LOG.error(getFormatedMessage(ERROR_IMPLEMENTED_CLASS, classname), ex);
		} catch (IllegalArgumentException ex) {
			LOG.error(getFormatedMessage(ERROR_IMPLEMENTED_CLASS, classname), ex);
		}	
	}
	
	/**
	 * <p>Carga el locale indicado en el fichero de configuración.</p>
	 * 
	 * @param rb Propiedades donde se encuentra configurado el locale
	 */
	private static void loadLocale(final Properties rb) {
		if (rb != null) {
			String localeStr = rb.getProperty(LOCALE_DEFAULT);
			if ((localeStr != null) && (!STRING_EMPTY.equals(localeStr.trim()))) {
				StringTokenizer st = new StringTokenizer(localeStr, STRING_SPACE);
				switch (st.countTokens()) {
					case 1: setLocale(new Locale(st.nextToken())); break;
					case 2: setLocale(new Locale(st.nextToken(), st.nextToken())); break;
					case 3: setLocale(new Locale(st.nextToken(), st.nextToken(), st.nextToken())); break;
					default: LOG.warn(WARN_UNKNOWN_LOCALE); setLocale(null); break;
				}
			} else {
				setLocale(null);
				LOG.trace(NOT_CONFIGURATED_LOCALE);
			}
		} else {
			setLocale(null);
		}
	}
	
	
	/**
	 * <p>Devuelve el manager configurado con el diccionario indicado.</p>
	 *  
	 * @param dictionary Clave que identifica el diccionario que se desea cargar
	 * @return Manager con el diccionario indicado. Si se ha dejado la factoría por defecto devuelve un manager del
	 * 		tipo Dumb si no se puede encontrar el diccionario.
	 */
	public static II18nManager getI18nManager(final String dictionary) {
		return getI18nManager(dictionary, locale);
	}
	
	/**
	 * <p>Devuelve el manager que gestiona el diccionario en el locale indicado.</p>
	 * 
	 * @param dictionary Clave que define el diccionario que se pide
	 * @param specificLocale Locale del que se requiere el diccionario, <code>null</code> si no hay Locale preferido
	 * @return Manager con el diccionario indicado. Si se ha dejado la factoría por defecto devuelve un manager del
	 * 		tipo Dumb si no se puede encontrar el diccionario.
	 */
	public static II18nManager getI18nManager(final String dictionary, final Locale specificLocale) {
		if (factory != null) {
			return factory.getI18nManager(dictionary, specificLocale);
		}
		// Si no hay factoria, sigue el fichero de configuración para lanzar la clase manager configurada
		synchronized (cache) {
			ManagerCached mc = cache.get(dictionary);
			if ((mc == null) || (!mc.isSameLocale(specificLocale))) {
				mc = new ManagerCached(instantiateManager(dictionary, specificLocale), specificLocale);
				cache.put(dictionary, mc);
			}
			return mc.getI18nCached();
		}
	}
	
	/**
	 * <p>Instancia el manager pedido.</p>
	 * <p>Si no hay configurado ningún manager de internacionalización carga el manager por defecto ({@link I18nDefaultManager}). Si tiene problemas en
	 * la instanciación del manager configurado devolverá un manager {@link I18nDumbManager}.</p>
	 * 
	 * @param dictionary Diccionario que debe gestionar el manager
	 * @param specificLocale Locale específico (<code>null</code> si no se especifica Locale)
	 * @return Manager instanciado e inicializado, I18nDumbManager si ha tenido problemas para encontrar el manager
	 * 			(ver {@link I18nDumbManager}).
	 */
	private static II18nManager instantiateManager(final String dictionary, final Locale specificLocale) {
		II18nManager manager = null;
		if (classManager != null) {
			try {
				manager = classManager.newInstance();
			} catch (InstantiationException ex) {
				LOG.error(getFormatedMessage(ERROR_INSTANTIATION_MANAGER, classManager), ex);
				manager = new I18nDumbManager();
			} catch (IllegalAccessException ex) {
				LOG.error(getFormatedMessage(ERROR_ACCESING_CLASS, classManager), ex);
				manager = new I18nDumbManager();
			} catch (ClassCastException ex) {
				LOG.error(getFormatedMessage(ERROR_CASTING_MANAGER, classManager), ex);
				manager = new I18nDumbManager();
			} catch (SecurityException ex) {
				LOG.error(getFormatedMessage(ERROR_ACCESING_CLASS, classManager), ex);
				manager = new I18nDumbManager();
			} catch (IllegalArgumentException ex) {
				LOG.error(getFormatedMessage(ERROR_IMPLEMENTED_CLASS, classManager), ex);
				manager = new I18nDumbManager();
			} catch (InvocationTargetException ex) {
				LOG.error(getFormatedMessage(ERROR_INSTANTIATION_MANAGER, classManager), ex);
				manager = new I18nDumbManager();
			}
		} else {
			manager = new I18nDefaultManager();
		}
		// Inicializa el manager de internacionalizacion
		try {
			manager.init(dictionary, specificLocale);
		} catch (DictionaryUnknownException ex) {
			LOG.error(getFormatedMessage(ERROR_INIT_MANAGER, dictionary), ex);
		}
		return manager;
	}
	
	/**
	 * Establece un nuevo <code>Locale</code> para la petición de diccionarios.
	 * 
	 * @param newLocale Nuevo <code>Locale</code> que se aplicará al pedir nuevos diccionarios.
	 */
	public static void setLocale(final Locale newLocale) {
		synchronized (I18nFactory.class) {
			locale = newLocale;
		}
	}
	
	/**
	 * <p>Incluye parámetros en un mensaje.</p>
	 * 
	 * @param message Mensaje a dar formato
	 * @param varargs Parámetros a incluir en el mensaje
	 * @return Mensaje con los parámetros incluidos
	 */
	private static String getFormatedMessage(final String message, final Object... varargs) {
		MessageFormat mf = new MessageFormat(message);
		return mf.format(varargs, new StringBuffer(), null).toString();
	}
}
