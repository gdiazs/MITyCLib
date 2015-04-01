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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;


/**
 * <p>Wrapper para permitir utilizar los servicios de varios dispositivos PKCS#11 (acceso a los servicios criptográficos de almacén y firma de varios
 * dispositivos externos).</p>
 * 
 */
public class MultiPKCS11Store implements IPKStoreManager {
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(MultiPKCS11Store.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	

	/** Información sobre los providers disponibles. */
	private ArrayList<IModuleData> providers = null;
	/** Gestionador de las contraseñas de acceso a los módulos PKCS11. */
	private IPassStoreKS passHandler = null;
	
	
	/**
	 * <p>Wrapper necesario para KeyStore para la obtención de contraseñas según el interfaz {@link IPassStoreKS}.</p>
	 */
	protected class InternCallbackHandlerProtection implements CallbackHandler {
		/** Manejador de las contraseñas. */
		private IPassStoreKS passHandler;
		
		/**
		 * <p>Constructor.</p>
		 * @param passwordHandler manejador de las contraseñas 
		 */
		public InternCallbackHandlerProtection(IPassStoreKS passwordHandler) {
			this.passHandler = passwordHandler;
		}
		
		/**
		 * <p>Maneja las consultas de acceso a contraseñas.</p>
		 * @param callbacks Peticiones de contraseñas recibidas
		 * @throws IOException Lanzada si hay errores en el acceso a la contraseña
		 * @throws UnsupportedCallbackException Lanzada si el tipo de Callback recibido no se aplica
		 * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
		 */
		public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if ((passHandler != null) &&
					(callbacks[i] instanceof PasswordCallback)) {
	                 PasswordCallback pc = (PasswordCallback) callbacks[i];
	                 pc.setPassword(passHandler.getPassword(null, pc.getPrompt()));
	             } else {
	                 throw new UnsupportedCallbackException(callbacks[i], I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_3));
	             }
	          }
		}
	}
	
	
	
	/**
	 * <p>Crea una instancia preparada para trabajar con los providers indicados en la configuración.</p>
	 * <p>En el campo de Alias del passwordHandler se indicará el nombre del módulo PKCS#11 que está requiriendo la contraseña.</p>
	 * @param config listado de providers que se utilizarán
	 * @param passwordHandler Gestionador de las contraseñas
	 */
	public MultiPKCS11Store(ConfigMultiPKCS11 config, IPassStoreKS passwordHandler) {
		this.passHandler = passwordHandler;
		providers = new ArrayList<IModuleData>();
		// inyecta los providers indicados
		if (config != null) {
			List<IModuleData> list = config.getProviders();
			if (list != null) {
				Iterator<IModuleData> itProvider = list.iterator();
				while (itProvider.hasNext()) {
					IModuleData pd = itProvider.next();
					providers.add(pd);
					if (LOG.isTraceEnabled()) {
						LOG.trace(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_9, pd.getName()));
					}
				}
			}
		}
	}
	
	/**
	 * <p>Actualiza los providers que hay instanciados por slot.</p>
	 */
	private void updateModules() {
		Iterator<IModuleData> itProv = providers.iterator();
		while (itProv.hasNext()) {
			IModuleData providerData = itProv.next();
			if (LOG.isTraceEnabled()) {
				LOG.trace(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_10, providerData.getName()));
			}
			providerData.updateModule();
		}
	}
	
	/**
	 * <p>Devuelve la cadena de certificados del certificado indicado.</p>
	 * <p>No implementado</p>
	 * @param certificate certificado origen de la cadena
	 * @return no implementado
	 * @throws CertStoreException Lanzada para indicar que esta función no está disponible
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getCertPath(java.security.cert.X509Certificate)
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_6));
	}

	/**
	 * <p>Recupera un proxy a la clave privada asociada a un certificado almacenado en un dispositivo P11.</p>
	 * @param certificate certificado almacenado en el p11
	 * @return Clave privada asociada
	 * @throws CertStoreException Lanzada cuando hay problemas de acceso al almacén
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getPrivateKey(java.security.cert.X509Certificate)
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		if (certificate instanceof P11CertificateProxy) {
			Provider provider = ((P11CertificateProxy) certificate).getProvider();
			try {
				KeyStore.LoadStoreParameter passwordHnd = new KeyStore.LoadStoreParameter() {
					public ProtectionParameter getProtectionParameter() {
						return new KeyStore.CallbackHandlerProtection(new InternCallbackHandlerProtection(passHandler));
					}
				};
				KeyStore ks = KeyStore.getInstance("PKCS11", provider);
				ks.load(passwordHnd);
				String alias = ks.getCertificateAlias(((P11CertificateProxy) certificate).getInternalCertificate());
				if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
					KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.CallbackHandlerProtection(new InternCallbackHandlerProtection(passHandler)));
					if (pkEntry != null) {
//						return new P11PrivateKeyProxy(pkEntry.getPrivateKey(), provider);
						return pkEntry.getPrivateKey();
					}
				}
			} catch (KeyStoreException ex) {
			} catch (CertificateException ex) {
			} catch (NoSuchAlgorithmException ex) {
			} catch (IOException ex) {
			} catch (UnrecoverableEntryException ex) {
			}
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_5));
		} else {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_4));
		}
	}

	/**
	 * <p>Devuelve el provider relacionado con este manejador de almacenes.</p>
     * @param cert Certificado para el que se necesita acceso al provider
	 * @return proveedor relacionado con el certificado
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getProvider(X509Certificate)
	 */
	public Provider getProvider(final X509Certificate cert) {
		Provider prov = null;
		if (cert instanceof P11CertificateProxy) {
			prov = ((P11CertificateProxy) cert).getProvider();
		}
		return prov;
	}

	/**
	 * <p>Recupera los certificados de firma disponibles en los módulos p11.</p>
	 * @return listado con los certificados disponibles en los módulos.
	 * @throws CertStoreException Lanzada si sucede algún error en el acceso a los módulos
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getSignCertificates()
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
		updateModules();
		Iterator<IModuleData> itProvData = providers.iterator();
		while (itProvData.hasNext()) {
			IModuleData providerData = itProvData.next();
			Iterator<IProviderData> itProvider = providerData.getProvidersData().iterator();
			while (itProvider.hasNext()) {
				IProviderData provider = itProvider.next();
				try {
					KeyStore.LoadStoreParameter passwordHnd = new KeyStore.LoadStoreParameter() {
						public ProtectionParameter getProtectionParameter() {
							return new KeyStore.CallbackHandlerProtection(new InternCallbackHandlerProtection(passHandler));
						}
					};
					KeyStore ks = KeyStore.getInstance(provider.getKeyStoreTypeName(), provider.getProvider());
					ks.load(passwordHnd);
					Enumeration<String> aliases = ks.aliases();
					while (aliases.hasMoreElements()) {
						String alias = aliases.nextElement();
						if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
							Certificate cert = ks.getCertificate(alias);
							if (cert instanceof X509Certificate) {
								certificates.add(new P11CertificateProxy((X509Certificate) cert, provider.getProvider()));
							}
						}
					}
				} catch (KeyStoreException ex) {
				} catch (CertificateException ex) {
				} catch (NoSuchAlgorithmException ex) {
				} catch (IOException ex) {
				}
			}
		}
		return certificates;
	}

	/**
	 * <p>Devuelve la cadena de certificados del certificado indicado.</p>
	 * <p>No implementado</p>
	 * @return no implementado
	 * @throws CertStoreException Lanzada para indicar que esta función no está disponible
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getTrustCertificates()
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_PKCS11_6));
	}

	/**
	 * <p>Devuelve los certificados que no tienen asociada una clave privada.</p>
	 * <p>No implementado</p>
	 * @return no implementado
	 * @throws CertStoreException Lanzada para indicar que esta función no está disponible
	 * @see es.mityc.javasign.pkstore.IPKStoreManager#getTrustCertificates()
	 */
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		// TODO: accede al KeyStore del provider asociado al dispositivo y pide los elementos que son TrustedCertificateEntry
		throw new UnsupportedOperationException("Not implemented yet");
	}
}
