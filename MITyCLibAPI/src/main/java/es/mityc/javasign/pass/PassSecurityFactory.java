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
package es.mityc.javasign.pass;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Factoría para gestionar los controladores de ofuscación.</p>
 * 
 * <p>Obtiene los managers disponibles para la ofuscación a través de los ficheros de configuración disponibles en
 * "<code>META-INF/pass/security.properties</code>".</p>
 * 
 * <p>Los ficheros de propiedades han de cumplir el formato:
 * <pre>
 * # En este fichero se indica qué clases son las encargadas de realizar las
 * # ofuscaciones y su configuración
 * # Formato:
 * #   &lt;clave&gt;=&lt;clase&gt;
 * # donde clave puede ser cualquier string y clase es la clase que implementa
 * # el interfaz es.mityc.javasign.pass.IPassSecurity y tiene por lo menos un
 * # constructor que admite un parámetro del tipo Properties.</pre>
 * </p>
 *
 */
public final class PassSecurityFactory {
	
	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(PassSecurityFactory.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME);
	
	/** Instancia de la factoría. */
	private static PassSecurityFactory instance;
	/** Conjunto de ofuscadores disponibles. */
	private List<Properties> props = null;
	
	/** Nombre del fichero de propiedades para la configuración de los managers de política. */
	private static final String PASS_SECURITY_FILE_CONF = "META-INF/pass/security.properties";
	

	/**
	 * Constructor.
	 *
	 */
	private PassSecurityFactory() {
		// Carga los gestionadores de ofuscación
		loadManagers();
	}
	
	/**
	 * <p>Carga los managers configurados en los ficheros de propiedades disponibles en 
	 * <code>META-INF/pass/security.properties</code>.</p>
	 */
	private void loadManagers() {
		ClassLoader cl = getClassLoader();
		try {
			Enumeration<URL> en = cl.getResources(PASS_SECURITY_FILE_CONF);
			props = new ArrayList<Properties>();
			while (en.hasMoreElements()) {
				URL url = en.nextElement();
				try {
					InputStream is = url.openStream();
					Properties properties = new Properties();
					properties.load(is);
					props.add(properties);
				} catch (IOException ex) {
					LOGGER.error(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_2, url, ex.getMessage()));
				}
			}
		} catch (IOException ex) {
			LOGGER.error(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_1, ex.getMessage()));
		}
		
	}
	
	/**
	 * <p>Obtiene un class loader relacionado con el peticionario de la instancia. Si no puede utiliza el propio que gestiona
	 * a la factoría.</p>
	 * @return ClassLoader conseguido
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
		return PassSecurityFactory.class.getClassLoader();
	}
	
	/**
	 * Para evitar problemas de sincronismo se instancia la primera vez que se referencia
	 */
	static {
		instance = getInstance();
	}
	
	/**
	 * <p>Devuelve una instancia de la factoría.</p>
	 *  
	 * @return instancia a la factoría
	 */
	public static PassSecurityFactory getInstance() {
		if (instance == null) {
			instance = new PassSecurityFactory();
		}
		return instance;
	}
	
	/**
	 * <p>Devuelve el ofuscador asociado a la clave indicada. Funciona como una factory que instancia un nuevo ofuscador en cada
	 * llamada.</p>
	 *  
	 * @param key Clave que tiene asociada un ofuscador
	 * @param defaultManager indica si se debe devolver un ofuscador nulo si no se encuentra el indicado
	 * @return Una instancia del ofuscador asociado o <code>null</code> si no hay ninguno asociado o no se puede instanciar.
	 */
	public IPassSecurity getPassSecurityManager(final String key, final boolean defaultManager) {
		IPassSecurity secManager = null;
		if ((props != null) && (props.size() > 0)) {
			Iterator<Properties> itProp = props.iterator();
			while (itProp.hasNext()) {
				Properties prop = itProp.next();
				String classname = prop.getProperty(key);
				if (classname != null) {
					try {
						ClassLoader cl = getClassLoader();
						Class< ? > manager = null;
						if (cl != null) {
							manager = cl.loadClass(classname);
						} else {
							manager = Class.forName(classname);
						}
						if (manager != null) {
							// comprueba que tiene un constructor al que pasar propiedades
							Constructor< ? > constructor = manager.getConstructor(Properties.class);
							if (constructor != null) {
								secManager = (IPassSecurity) constructor.newInstance(prop);
							} else {
								// si no lo hay lo intenta con uno por defecto
								constructor = manager.getConstructor((Class[]) null);
								if (constructor != null) {
									secManager = (IPassSecurity) constructor.newInstance();
								}
							}
						}
					} catch (InstantiationException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (IllegalAccessException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (ClassNotFoundException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (ClassCastException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (SecurityException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (NoSuchMethodException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (IllegalArgumentException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					} catch (InvocationTargetException ex) {
						LOGGER.warn(I18N.getLocalMessage(ConstantsAPI.I18N_PASS_SECURITY_3, ex.getMessage()));
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("", ex);
						}
					}
					// Si no consigue un manager, al menos informa con el genérico
					if ((secManager == null) && (defaultManager)) {
						secManager = new NullPassSecurity();
					}
				}
			}
		}
		// Si no consigue un manager, al menos informa con el genérico
		if ((secManager == null) && (defaultManager)) {
			secManager = new NullPassSecurity();
		}
		return secManager;
	}

}
