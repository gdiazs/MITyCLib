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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.ConstantsCert;

/**
 * <p>Configuración de proveedores de acceso a PKCS#11.</p>
 */
public class ConfigMultiPKCS11 {
	/** Lista de providers disponibles en esta configuración. */
	private ArrayList<IModuleData> providers = new ArrayList<IModuleData>();
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Nombre del módulo que conecta con las clases de SunPKCS11. */
	private static final String MODULE_CLASS = "es.mityc.javasign.pkstore.pkcs11.SunP11ModuleData";
	/** Nombre de la clase provider de Sun para módulos PKCS 11. */
	private static final String SUN_CLASS = "sun.security.pkcs11.SunPKCS11";

	/**
	 * <p>Constructor.</p> 
	 */
	public ConfigMultiPKCS11() {
	}
	
	/**
	 * <p>Añade un nuevo provider del tipo Sun para el acceso a módulos PKCS#11.</p>
	 * @param name Nombre del módulo PKCS#11
	 * @param lib Ruta de la librería PKCS#11
	 * @throws NoSuchProviderException lanzada si no se encuentran las clases de SunPKCS11
	 */
	public void addSunProvider(final String name, final String lib) throws NoSuchProviderException {
		testSunPKCS11Library();
		providers.add(getSunP11ModuleData(name, lib));
	}
	
	/**
	 * <p>Instancia de nabera dinámica el módulo P11 de Sun.</p>
	 * @param name Nombre del proveedor 
	 * @param lib Librería P11 de acceso al módulo
	 * @return Módulo P11
	 * @throws NoSuchProviderException lanzada si no se encuentran las clases de SunPKCS11
	 */
	private IModuleData getSunP11ModuleData(final String name, final String lib) throws NoSuchProviderException {
		try {
			Class< ? > prov = Class.forName(MODULE_CLASS);
			Constructor< ? > constructor = prov.getConstructor(String.class, String.class);
			return (IModuleData) constructor.newInstance(name, lib);
		} catch (ClassNotFoundException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (SecurityException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (NoSuchMethodException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (IllegalArgumentException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (InstantiationException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (IllegalAccessException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		} catch (InvocationTargetException ex) {
			throw new NoSuchProviderException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_16, ex.getMessage()));
		}
	}
	
	/**
	 * <p>Comprueba si la librería de sunpkcs11 está disponible.</p>
	 * <p>Si la librería no está disponible lanza una excepción del tipo ProviderException.</p>
	 * @throws NoSuchProviderException lanzada si no se encuentran las clases de SunPKCS11 
	 */
	public void testSunPKCS11Library() throws NoSuchProviderException {
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
	 * <p>Devuelve la lista de providers configurado.</p>
	 * @return lista de providers
	 */
	protected List<IModuleData> getProviders() {
		return providers;
	}
}
