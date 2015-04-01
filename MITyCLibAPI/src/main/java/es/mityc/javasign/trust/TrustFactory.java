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

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Factoría que gestiona las instancias de validadores de confianza.</p>
 * 
 * <p>Esta factoría sirve como punto de entrada para obtener managers de confianza. Se utiliza bajo el patrón singleton, permitiendo
 * ser superpuesta por otra factoría de managers de confianza si se define un fichero de propiedades en 
 * <code>META-INF/trust/trustservices.properties</code> con la especificación:
 * <pre>
 * # Propiedad que indica la clase que hará de factoría de servicios de confianza
 * services.trust.factory.class=
 * </pre>.</p>
 * 
 * <p>El modo de uso de la factoría estándar es parametrizar el fichero de propiedades <code>trust/trust.properties</code> con el formato:
 * <pre>
 * # Fichero de configuración de los validadores de confianza disponibles
 * # Se debe emparejar una clave con el nombre de la clase que implementa TrustAbstract y que realizará las labores de validador
 * # Formato:
 * #   &lt;clave&gt;=&lt;clase&gt;
 * </pre>
 * indicando parejas de claves y clases asociadas. Cuando se solicite a la factoría una clave identificativa del manager de confianza
 * se instanciará el indicado según la parametrización.</p>
 * 
 */
public class TrustFactory {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(TrustFactory.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME);

	/** Nombre del método que devuelve una instancia. */
	private static final String METHOD_GET_INSTANCE = "getInstance";
	/** Nombre del método que devuelve una nueva instancia. */
	private static final String METHOD_NEW_INSTANCE = "newInstance";
	/** Cadena vacía. */
	private static final String STRING_EMPTY = "";

	
	/** Fichero de configuración de factoría de managers de confianza. */
	private static final String TRUST_SERVICES_FILE_CONF = "META-INF/trust/trustservices.properties";
	/** Nombre de la propiedad que indica la nueva clase de factoría de managers de confianza. */
	private static final String TRUST_SERVICES_FACTORY_CLASS = "services.trust.factory.class";

	/** Fichero de configuración de managers de confianza. */
	private static final String TRUST_FILE_CONF = "trust/trust.properties";
	/** Valor indicado cuando no se quiere ningún manager asociado a la clave. */
	private static final String TRUSTER_PROP_NO_AVALAIBLE = "none";

	/** Propiedades que tienen la configuración de claves vs managers de confianza. */ 
	private Properties props = null;
	/** Instancia encargada de la gestión de los managers de confianza. */
	private static TrustFactory instance = null;
	
	/**
	 * Constructor.
	 *
	 */
	protected TrustFactory() {
		loadConfig();
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
		return TrustFactory.class.getClassLoader();
	}
	
	/**
	 * <p>Carga los managers de confianza indicados en los ficheros de propiedades disponibles en 
	 * <code>trust/trust.properties</code>.</p>
	 */
	private void loadConfig() {
		ClassLoader cl = getClassLoader();
		try {
			// cambia el orden del listado de recursos
			ArrayList<URL> resources = new ArrayList<URL>();
			Enumeration<URL> en = cl.getResources(TRUST_FILE_CONF);
			while (en.hasMoreElements()) {
				resources.add(0, en.nextElement());
			}
			// carga cada conjunto de propiedades de atrás hacia adelante para respetar el orden del classpath
			Properties base = null;
			Iterator<URL> itResources = resources.iterator();
			while (itResources.hasNext()) {
				URL url = itResources.next();
				try {
					if (LOG.isDebugEnabled())
						LOG.debug("Cargando el fichero de propiedades de listas de confianza: " + url);
					InputStream is = url.openStream();
					Properties properties = new Properties(base);
					properties.load(is);
					base = properties;
				} catch (IOException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_9, url, ex.getMessage()));
				}
			}
			props = base;
		} catch (IOException ex) {
			LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_1, ex.getMessage()));
		}
	}

	/**
	 * <p>Devuelve una instancia del manager de confianza.</p>
	 * @return instancia de factoría de clases comprobadoras de confianza
	 */
	public static TrustFactory getInstance() {
		if (instance == null) {
			// obtiene la configuración de TrustFactory por defecto
			try {
				String classname = null;
				// Comprueba si se ha indicado que se cambie la factoría
				ClassLoader cl = getClassLoader();
				InputStream is = cl.getResourceAsStream(TRUST_SERVICES_FILE_CONF);
				if (is != null) {
					Properties rb = new Properties();
					try {
						rb.load(is);
						classname = rb.getProperty(TRUST_SERVICES_FACTORY_CLASS);
					} catch (IOException ex) {
						LOG.warn(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_9, TRUST_SERVICES_FACTORY_CLASS, ex.getMessage()));
					}
				}
				// Si se ha indicado una nueva factoría la intenta cargar
				if (classname != null) {
					try {
						Class< ? > classFactory = null;
						if (cl != null) {
							classFactory = cl.loadClass(classname);
						} else {
							classFactory = Class.forName(classname);
						}
						if (classFactory != null) {
							Method method = classFactory.getDeclaredMethod(METHOD_NEW_INSTANCE);
							Class< ? > returnType = method.getReturnType();
							if ((returnType != null) && (returnType.isAssignableFrom(TrustFactory.class))) {
								instance = (TrustFactory) method.invoke(null);
							}
						}
					} catch (IllegalAccessException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_8, classname));
						if (LOG.isDebugEnabled()) {
							LOG.debug(STRING_EMPTY, ex);
						}
					} catch (ClassNotFoundException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_8, classname));
						if (LOG.isDebugEnabled()) {
							LOG.debug(STRING_EMPTY, ex);
						}
					} catch (ClassCastException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_8, classname));
						if (LOG.isDebugEnabled()) {
							LOG.debug(STRING_EMPTY, ex);
						}
					} catch (NoSuchMethodException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_8, classname));
						if (LOG.isDebugEnabled()) {
							LOG.debug(STRING_EMPTY, ex);
						}
					} catch (IllegalArgumentException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_8, classname));
						if (LOG.isDebugEnabled()) {
							LOG.debug(STRING_EMPTY, ex);
						}
					} catch (InvocationTargetException ex) {
						LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_8, classname));
						if (LOG.isDebugEnabled()) {
							LOG.debug(STRING_EMPTY, ex);
						}
					}
				}
			} catch (MissingResourceException ex) {
			}
			if (instance == null) {
				instance = newInstance();
			}
		}
		return instance;
	}
	
	/**
	 * <p>Una factoría que quiera sustituir a esta deberá implementar este método devolviendo una instancia de sí misma.</p>
	 * 
	 * @return una instancia de esta factoría de clases comprobadoras de confianza
	 */
	protected static TrustFactory newInstance() {
		return new TrustFactory();
	}
	
	
	/**
	 * <p>Establece la factoría por defecto para obtener los validadores de confianza.</p>
	 * 
	 * @param factory Factoría que se quiere utilizar para generar los validadores de confianza
	 */
	public static void setDefault(final TrustFactory factory) {
		instance = factory;
	}
	
	/**
	 * Devuelve el nombre de la clase en función de la clave.
	 * 
	 * Este método se debe sobreescribir si se quiere una factoría que mantenga su propio sistema de selección de clases de validadores
	 * de confianza.
	 * 
	 * @param key identificador del manager de confianza que se busca
	 * @return Nombre de la clase que implementa la clase de validador de confianza
	 */
	protected String getClassname(final String key) {
		String classname = props.getProperty(key);
		if (classname == null) {
			LOG.warn(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_6, key));
		}
		return classname;
	}
	

	/**
	 * Devuelve el validador de confianza asociado a la clave indicada. Funciona como una factory que instancia un 
	 * nuevo validador en cada llamada.
	 *  
	 * @param key Clave para identificar al validador
	 * @return Una instancia del validador de confianza o <code>null</code> si no hay ninguno asociado o no 
	 * 		   se puede instanciar.
	 */
	public TrustAbstract getTruster(final String key) {
		TrustAbstract truster = null;
		if (instance != null) {
			String classname = getClassname(key);
			if ((classname != null) && (!TRUSTER_PROP_NO_AVALAIBLE.equals(classname.trim().toLowerCase()))) {
				try {
					ClassLoader cl = getClassLoader();
					Class< ? > classTruster = null;
					if (cl != null) {
						classTruster = cl.loadClass(classname);
					} else {
						classTruster = Class.forName(classname);
					}
					if (classTruster != null) {
						Method method = classTruster.getMethod(METHOD_GET_INSTANCE);
						Object obj = method.invoke(null);
						if (obj instanceof TrustAbstract) {
							truster = (TrustAbstract) obj;
						}
					}
				} catch (IllegalAccessException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_3, key, classname));
					if (LOG.isDebugEnabled()) {
						LOG.debug(STRING_EMPTY, ex);
					}
				} catch (ClassNotFoundException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_4, key, classname));
					if (LOG.isDebugEnabled()) {
						LOG.debug(STRING_EMPTY, ex);
					}
				} catch (ClassCastException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_5, key, classname));
					if (LOG.isDebugEnabled()) {
						LOG.debug(STRING_EMPTY, ex);
					}
				} catch (NoSuchMethodException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_6, key, classname));
					if (LOG.isDebugEnabled()) {
						LOG.debug(STRING_EMPTY, ex);
					}
				} catch (IllegalArgumentException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_3, key, classname));
					if (LOG.isDebugEnabled()) {
						LOG.debug(STRING_EMPTY, ex);
					}
				} catch (InvocationTargetException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_TRUST_2, key, classname));
					if (LOG.isDebugEnabled()) {
						LOG.debug(STRING_EMPTY, ex);
					}
				}
			}
		}
		return truster;
	}
	
}
