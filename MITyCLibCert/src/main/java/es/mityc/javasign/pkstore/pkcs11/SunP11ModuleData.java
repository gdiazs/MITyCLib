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
package es.mityc.javasign.pkstore.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.action.GetPropertyAction;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;


/**
 * <p>Clase que implementa el acceso a módulos PKCS#11 a través del proveedor de sun SunPKCS11.</p>
 * <p>Esta clase está asociada a clases internas del proveedor de seguridad SunPKCS11. Se adapta dinámicamente a las implementaciones
 * de java 5 y java 6.</p>
 */
public final class SunP11ModuleData implements IModuleData {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(SunP11ModuleData.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);

	/** Nombre de la clase provider de Sun para módulos PKCS 11. */
	private static final String SUN_CLASS = "sun.security.pkcs11.SunPKCS11";
	
	
	/** Cadena base de configuración para el acceso a SunPKCS11. */
	private static final String CONFIG_BASE = "name={0}\r\n" +
			"library={1}\r\n" +
			"attributes=compatibility\r\n" +
			"showInfo=true\r\n" +
			"nssArgs=\"configdir='C:\\Users\\msomavilla\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\krsd57o8.default'"+
			" certPrefix='' keyPrefix='' secmod='secmod.db'\"\r\n" +
			"slot={2}";	
	
	/** Nombre del tipo de KeyStore que gestiona Sun con SunPKCS11. */
	private static final String KEYSTORE_TYPE = "PKCS11";
	/** Nombre del método que devuelve una instancia del elemento PKCS11. */
	private static final String PKCS11_INSTANTIATE_METHOD = "getInstance";
	/** Parámetro extra en la instanciación de un elemento PKCS11 en java 6. */
	private static final String PKCS11_PARAM_JAVA6 = "C_GetFunctionList";
	/** SlotsID escaneados en caso de no disponer de información sobre los slots disponibles. */
	private static final long[] SLOTS_DEFAULT = { };
	/** Código de error de comunicación con el dispositivo. */
	private static final long CKR_DEVICE_ERROR_CODE = 48;
	/** Método de acceso al objeto PKCS 11 en java 6. */
	private Method pkcs11MethodJ6 = null;
	/** Método de acceso al objeto PKCS 11 en java 5. */
	private Method pkcs11MethodJ5 = null;

	/** Nombre del módulo. */
	private String name;
	/** Ruta de la librería. */
	private String lib;
	/** Listado de providers asociados a slots. */
	private ArrayList<IProviderData> providers = new ArrayList<IProviderData>();
	
	
	/**
	 * <p>Constructor.</p>
	 * @param provName nombre del módulo PKCS#11
	 * @param provLib ruta de la librería PKCS#11 
	 * @throws NoSuchProviderException si no se encuentran las clases de SunPKCS11 
	 */
	public SunP11ModuleData(final String provName, final String provLib) throws NoSuchProviderException {
		this.name = new String(provName);
		this.lib = new String(provLib);
		testSunPKCS11Library();
	}
	
	/**
	 * <p>Comprueba si la librería de sunpkcs11 está disponible.</p>
	 * <p>Si la librería no está disponible lanza una excepción del tipo ProviderException.</p>
	 * @throws NoSuchProviderException si no se encuentran las clases de SunPKCS11 
	 */
	private void testSunPKCS11Library() throws NoSuchProviderException {
		try {
			Class< ? > prov = Class.forName(SUN_CLASS);
			if (prov == null) {
				throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_17)));
			}
		} catch (ClassNotFoundException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));		
		}
	}
	
	/**
	 * <p>Devuelve la ruta de la librería.</p>
	 * @return ruta de la librería
	 */
	public String getLib() {
		return lib;
	}
	
	/**
	 * <p>Devuelve el nombre del módulo.</p>
	 * @return nombre del módulo
	 */
	public String getName() {
		return name;
	}

	/**
	 * <p>Devuelve un listado con los providers disponibles ya asociados a slots.</p>
	 * @return listado de providers
	 */
	@SuppressWarnings("unchecked")
	public synchronized List<IProviderData> getProvidersData() {
		return (providers != null) ? ((List<IProviderData>) providers.clone()) : new ArrayList<IProviderData>();
	}
	/**
	 * <p>Reajusta los providers existentes asociados a los slots.</p>
	 * <p>Si se encuentra que en un slot no hay asignado un provider lo crea, y si se encuentra que hay un slot que ya no está disponible
	 * elimina el provider.</p>
	 * @param slots Slot IDs actuales 
	 */
	private synchronized void adjustProviders(final long[] slots) {
		// TODO: proteger la sincronización para el nuevo listado de providers
		ArrayList<IProviderData> newProviders = new ArrayList<IProviderData>();
		for (int i = 0; i < slots.length; i++) {
			int pos = providers.indexOf(new Long(slots[i]));
			if (pos > -1) {
				newProviders.add(providers.get(pos));
			} else {
				// Crea un nuevo provider
				try {
					String config = MessageFormat.format(CONFIG_BASE, getName() + slots[i], getLib(), slots[i]);
					Provider provider = getSunPKCS11(new ByteArrayInputStream(config.getBytes()));
					newProviders.add(new SunP11SlotData(provider, slots[i], KEYSTORE_TYPE));
					if (LOG.isTraceEnabled()) {
						LOG.trace(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_8, provider.getName(), slots[i]));
					}
				} catch (NoSuchProviderException ex) {
					if (LOG.isTraceEnabled()) {
						LOG.trace(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_2, getName(), slots[i]));
						LOG.error("", ex);
					}
				}
			}
		}
		providers = newProviders;
	}
	
	/**
	 * <p>Carga el proveedor SunPKCS11 de manera dinámica.</p>
	 * <p>Lanza una excepción {@link java.security.ProviderException}  si no se puede acceder al módulo de sun para acceder a P11.</p>
	 * @param is InputStream con la configuración compatible con SunPKCS11
	 * @return Provider SunPKCS11 si está disponibl
	 * @throws NoSuchProviderException si no se encuentran las clases de SunPKCS11 
	 */
	private Provider getSunPKCS11(InputStream is) throws NoSuchProviderException {
		try {
			Class< ? > prov = Class.forName(SUN_CLASS);
			Constructor< ? > constructor = prov.getConstructor(InputStream.class);
			AccessController.doPrivileged(new GetPropertyAction("sun.security.pkcs11.allowSingleThreadedModules"));
			return (Provider) new SunPKCS11(is);
		} catch (ClassNotFoundException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (SecurityException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (NoSuchMethodException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (IllegalArgumentException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		}
	}

	/**
	 * <p>Actualiza los slots disponibles del sistema con los providers PKCS#11 de Sun para buscar los dispositivos conectados en cada slot
	 * que se ajustan al tipo gestionado por este módulo.</p>
	 */
	public void updateModule() {
		long[] slots = getSlots();
		if (LOG.isTraceEnabled()) {
			LOG.trace(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_11, slots.length));
		}
		slots = new long[2];
		slots [0] = 1;
		adjustProviders(slots);
	}
	
	/**
	 * <p>Guarda en el log los slots disponibles.</p> 
	 * @param slots slots disponibles
	 * @param message Cabecera del mensaje de slots disponibles
	 */
	private void logSlots(final long[] slots, final String message) {
		StringBuffer sb = new StringBuffer("");
		if ((slots != null) &&
			(slots.length > 0)) {
			for (int i = 0; i < slots.length; i++) {
				sb.append(slots[i]);
				if (i < (slots.length - 1)) {
					sb.append(", ");
				}
			}
		} else {
			sb.append(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_13));
		}
		LOG.trace(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_12, message, (slots != null) ? slots.length : 0, sb.toString()));
	}
	
	/**
	 * <p>Elimina los slots que no son reconocidos por la librería.</p>
	 * @param pkcs11 Módulo JNI para acceder a la información del dispositivo
	 * @param slots Slots actuales donde hay tokens introducidos
	 * @return Slots que sí son reconocidos por la librería
	 */
	private long[] filterSlots(final PKCS11 pkcs11, final long[] slots) {
		ArrayList<Long> list = new ArrayList<Long>();
		if (slots != null) {
			for (int i = 0; i < slots.length; i++) {
				try {
					CK_TOKEN_INFO tokenInfo = pkcs11.C_GetTokenInfo(slots[i]);
					list.add(new Long(slots[i]));
				} catch (PKCS11Exception ex) {
					// WORKAROUND para freeze DNIe + Firefox
					// Reintenta el acceso al dispositivo si hay error en la comunicación
					if (ex.getErrorCode() == CKR_DEVICE_ERROR_CODE) {
						try {
							CK_TOKEN_INFO tokenInfo = pkcs11.C_GetTokenInfo(slots[i]);
							list.add(new Long(slots[i]));
						} catch (PKCS11Exception ex1) {
						}
					}
				}
			}
		}
		long[] newSlots = new long[list.size()];
		for (int i = 0; i < list.size(); i++) {
			newSlots[i] = list.get(i).longValue();
		}
		return newSlots;
	}
	
	/**
	 * <p>Devuelve las IDs de slots disponibles para el módulo indicado.</p>
	 * @return Array de slots disponibles, SLOTS_DEFAULT si no hay información sobre slots disponibles
	 */
	private long[] getSlots() {
		long[] slots = null;
		CK_C_INITIALIZE_ARGS ckCInitializeArgs = new CK_C_INITIALIZE_ARGS();
		ckCInitializeArgs.flags = 2L;
		PKCS11 pkcs11 = getPKSC11(getLib(), ckCInitializeArgs);
		if (pkcs11 != null) {
			try {
				// Todos los nodos ocupados
				slots = pkcs11.C_GetSlotList(true);
				if (LOG.isTraceEnabled()) {
					logSlots(slots, I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_14));
				}
				// Filtra los slots que no son reconocidos por este provider
				slots = filterSlots(pkcs11, slots);
				if (LOG.isTraceEnabled()) {
					logSlots(slots, I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_15, getName()));
				}
			} catch (PKCS11Exception ex) {
				// No provocar una inicialización del token no multithreading porque podría dejar el token no disponible para nadie
			}
		}
		return (slots != null) ? slots : SLOTS_DEFAULT;
	}
	
	/**
	 * <p>Devuelve una instancia del objeto del tipo PKCS11.</p>
	 * <p>Intenta recuperar el objeto disponible en Java6, sino puede lo busca bajo el formato de java5.</p>
	 * @param libname Nombre de la librería PKCS11
	 * @param args argumentos de inicialización del elementos PKCS11
	 * @return Objeto PKCS11, <code>null</code> si no se puede instanciar
	 */
	private PKCS11 getPKSC11(final String libname, final CK_C_INITIALIZE_ARGS args) {
		PKCS11 pkcs11 = null;
		// Primero busca la instanciación de java 6
		try {
			if ((pkcs11MethodJ6 == null) && (pkcs11MethodJ5 == null)) {
				pkcs11MethodJ6 = PKCS11.class.getMethod(PKCS11_INSTANTIATE_METHOD, String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class);
			}
			if (pkcs11MethodJ6 != null) {
				Object res = pkcs11MethodJ6.invoke(null, libname, PKCS11_PARAM_JAVA6, args, false);
				if ((res != null) && 
					(res instanceof PKCS11)) {
					pkcs11 = (PKCS11) res;
				}
			}
		} catch (NoSuchMethodException ex) {
			if (LOG.isTraceEnabled()) {
				LOG.error("", ex);
			}
		} catch (InvocationTargetException ex) {
			if (LOG.isTraceEnabled()) {
				LOG.error("", ex);
			}
		} catch (IllegalAccessException ex) {
			if (LOG.isTraceEnabled()) {
				LOG.error("", ex);
			}
		} catch (IllegalArgumentException ex) {
			if (LOG.isTraceEnabled()) {
				LOG.error("", ex);
			}
		}

		// Si no lo encuentra busca la instanciación de java 5
		if (pkcs11 == null) {
			try {
				if (pkcs11MethodJ5 == null) {
					pkcs11MethodJ5 = PKCS11.class.getMethod(PKCS11_INSTANTIATE_METHOD, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class);
				}
				if (pkcs11MethodJ5 != null) {
					Object res = pkcs11MethodJ5.invoke(null, libname, args, false);
					if ((res != null) &&
						(res instanceof PKCS11)) {
						pkcs11 = (PKCS11) res;
					}
				}
			} catch (NoSuchMethodException ex) {
				if (LOG.isTraceEnabled()) {
					LOG.error("", ex);
				}
			} catch (InvocationTargetException ex) {
				if (LOG.isTraceEnabled()) {
					LOG.error("", ex);
				}
			} catch (IllegalAccessException ex) {
				if (LOG.isTraceEnabled()) {
					LOG.error("", ex);
				}
			} catch (IllegalArgumentException ex) {
				if (LOG.isTraceEnabled()) {
					LOG.error("", ex);
				}
			}
		}
		
		return pkcs11;
	}
}
