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
package es.mityc.javasign.bridge;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;

/**
 * <p>Factoría para los facades de servicios de firma.</p>
 * 
 * <p>Mediante esta factoría, bajo patrón singleton, se instancia los facades que dan servicio de firma. Estos facades deberán contar con
 * un constructor sin parámetros que será el llamado para generar la instancia que se entregará.</p>
 * <p>Los facades a instanciar se configuran mediante un fichero de propiedades (<code>bridge/sign.properties</code>), a través de su propiedad
 * <code>facade.sign.class</code> en la cual se indica la clase facade:
 * <pre>
 * # Indica la clase que implementa el interfaz ISignFacade que dará los servicios de firma
 * facade.sign.class=
 * </pre>
 * </p>
 * 
 */
public final class SignFactory {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(SignFactory.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsAPI.LIB_NAME);
	
	/** Instancia única de la factoría. */
	private static SignFactory instance;
	/** Propiedades de configuración de la factoría. */
	private Properties props = null;
	
	/** Nombre del fichero de propiedades que contiene la configuración de la factoría. */
	private static final String SIGN_FILE_CONF = "bridge/sign.properties";
	/** Nombre de la propiedad que tiene la clase de facade de firma. */
	private static final String PROP_FACADE_CLASS = "facade.sign.class";
	

	/**
	 * <p>Constructor.</p>
	 * <p>Recupera la configuración de la factoría de los facade de firma.</p>
	 */
	private SignFactory() {
		// Carga las propiedades
		InputStream is = getClassLoader().getResourceAsStream(SIGN_FILE_CONF);
		if (is != null) {
			try {
				props = new Properties();
				props.load(is);
			} catch (IOException ex) {
				LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_1));
			}
		} else {
			LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_1));
		}
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
		return SignFactory.class.getClassLoader();
	}

	
	/**
	 * Para evitar problemas de sincronismo se instancia la primera vez que se referencia
	 */
	static {
		instance = getInstance();
	}
	
	/**
	 * Devuelve una instancia la factoría de facades de servicios de firma.
	 *  
	 * @return Instancia de la factoría
	 */
	public static SignFactory getInstance() {
		if (instance == null) {
			instance = new SignFactory();
		}
		return instance;
	}
	
	/**
	 * <p>Devuelve el facade configurado para dar servicios de firma.</p> 
	 *  
	 * @return Una instancia del validador de policy asociado o <code>null</code> si no hay ninguno asociado o no se puede instanciar.
	 */
	public ISignFacade getSignFacade() {
		ISignFacade signFacade = null;
		if (props != null) {
			String classname = props.getProperty(PROP_FACADE_CLASS);
			if ((classname != null) && (!"".equals(classname.trim()))) {
				try {
					ClassLoader cl = getClassLoader();
					Class< ? > classTemp = null;
					if (cl != null) {
						classTemp = cl.loadClass(classname);
					} else {
						classTemp = Class.forName(classname);
					}
					if (classTemp != null) {
						signFacade = (ISignFacade) classTemp.getConstructor((Class[]) null).newInstance();
					}
				} catch (InstantiationException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_2));
					if (LOG.isDebugEnabled()) {
						LOG.error("", ex);
					}
				} catch (InvocationTargetException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_2));
					if (LOG.isDebugEnabled()) {
						LOG.error("", ex);
					}
				} catch (IllegalAccessException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_3));
					if (LOG.isDebugEnabled()) {
						LOG.error("", ex);
					}
				} catch (ClassNotFoundException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_4, classname));
					if (LOG.isDebugEnabled()) {
						LOG.error("", ex);
					}
				} catch (ClassCastException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_5));
					if (LOG.isDebugEnabled()) {
						LOG.error("", ex);
					}
				} catch (NoSuchMethodException ex) {
					LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_5));
					if (LOG.isDebugEnabled()) {
						LOG.error("", ex);
					}
				}
			} else {
				LOG.error(I18N.getLocalMessage(ConstantsAPI.I18N_BRIDGE_6));
			}
		}
		return signFacade;
	}
}
