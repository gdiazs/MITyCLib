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
package es.mityc.javasign.pkstore.keystore;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPassStoreKS;

/**
 * <p>Utilidades de tratamiento de keystores.</p>
 * 
 */
public final class KeyTool {
	
	/** Logger. */
	private static final Log LOG = LogFactory.getLog(KeyTool.class);
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
	/** Cadena vacía. */
	static final char[] EMPTY_STRING = "".toCharArray();
	
	/**
	 * <p>Recupera los certificados que pueden firmar contenidos en el KeyStore.</p>
	 * @param ks keystore en el que buscar los certificados
	 * @return Listado de certificados con clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con el KeyStore interno
	 */
	public static List<X509Certificate> getCertificatesWithKeys(final KeyStore ks) throws CertStoreException {
		return getCertificates(ks, true);
	}
	
	/**
	 * <p>Recupera los certificados que pueden firmar contenidos en el KeyStore.</p>
	 * @param ks keystore en el que buscar los certificados
	 * @return Listado de certificados con clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con el KeyStore interno
	 */
	public static List<X509Certificate> getCertificatesWithoutKeys(final KeyStore ks) throws CertStoreException {
		return getCertificates(ks, false);
	}
	
	/**
	 * <p>Recupera los certificados que pueden firmar contenidos en el KeyStore.</p>
	 * @param ks keystore en el que buscar los certificados
	 * @param getPrivate <code>true</code> para obtener sólo los certificados con clave privada.
	 * 					 <code>false</code> para obtener los certificados sin clave priva asociada. 
	 * @return Listado de certificados con clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con el KeyStore interno
	 */
	private static List<X509Certificate> getCertificates(final KeyStore ks, boolean getPrivates) throws CertStoreException {
		try {
			Enumeration<String>total = ks.aliases();
			ArrayList<X509Certificate> listaPrivada = new ArrayList<X509Certificate>();
			ArrayList<X509Certificate> listaPublica = new ArrayList<X509Certificate>();
			while (total.hasMoreElements()) {
				String alias = total.nextElement();
				Certificate cert = ks.getCertificate(alias);
				if (ks.isKeyEntry(alias)) {
					if (LOG.isTraceEnabled()) {
						LOG.trace("Certificado con alias " + alias + " tiene un key asociada");
					}

					if (cert instanceof X509Certificate) {
						listaPrivada.add((X509Certificate) cert);
					}
				} else {
					if (LOG.isTraceEnabled()) {
						LOG.trace("Certificado con alias " + alias + " no tiene un key asociada");
					}

					if (cert instanceof X509Certificate) {
						listaPublica.add((X509Certificate) cert);
					}
				}
			}
			
			if (getPrivates) {
				return listaPrivada;
			} else {
				return listaPublica;
			}
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_1, ks.getType(), ex.getMessage(), ex));
		}
	}
	
	/**
	 * <p>Obtiene acceso a la clave privada de un certificado específico.</p>
	 * <p>Busca en primer lugar el primer alias que coincide con el certificado, si no tiene clave asociada pasa a buscar por todos los
	 * alias del almacén cuál tiene clave privada y de ellos busca el certificado que coincida con el provisto.</p>
	 * @param ks Keystore con las claves y certificados
	 * @param certificate Certificado del que se quiere su clave privada
	 * @param passHandler manejador de las contraseñas
	 * @param nullPassword Cadena de prueba para clave no protegida
	 * @return Clave privada
	 * @throws CertStoreException Lanzada cuando no consigue acceso a la clave por los siguientes motivos:
	 * 			<ul>
	 * 				<li>fallo de contraseña</li>
	 * 				<li>ausencia de certificado en el keystore</li>
	 * 				<li>ausencia de clave (está el certificado pero no tiene clave asociada, es un TrustedCertificate)</li>
	 * 			</ul>
	 */
	public static PrivateKey findPrivateKey(final KeyStore ks, final X509Certificate certificate, final IPassStoreKS passHandler, final char[] nullPassword) throws CertStoreException {
		try {
			String alias = ks.getCertificateAlias(certificate);
			if (!ks.isKeyEntry(alias)) {
				LOG.trace("Certificado con alias " + alias + " no tiene clave. Se procede a búsqueda de todos los certificados con clave.");
				try {
					Enumeration<String>total = ks.aliases();
					while (total.hasMoreElements()) {
						String keyAlias = total.nextElement();
						if (ks.isKeyEntry(keyAlias)) {
							Certificate cert = ks.getCertificate(keyAlias);
							if (cert instanceof X509Certificate) {
								if (cert.equals(certificate)) {
									alias = keyAlias;
									LOG.trace("Certificado con clave coincide con certificado buscado: " + alias);
									break;
								}
							}
						}
					}
				} catch (KeyStoreException ex) {
					throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_1, ex.getMessage(), ex));
				}
			}
			if (alias == null) {
	        	throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_6));
			}
			
			if (LOG.isTraceEnabled()) {
				LOG.trace("Pidiendo key asociado al alias " + alias);
			}
			PrivateKey resultado = null;
			try {
				resultado = (PrivateKey) ks.getKey(alias, nullPassword);
			} catch (UnrecoverableKeyException e) {
				char[] passwd = passHandler.getPassword(certificate, alias);
				resultado = (PrivateKey) ks.getKey(alias, passwd);
			}
			if (resultado == null) {
				throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_5));
			} else {
				return resultado;
			}
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_2, ex.getMessage(), ex));
		} catch (UnrecoverableKeyException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_4, ex.getMessage()));		
		}
	}
	
	/**
	 * <p>Obtiene acceso a la clave privada de un certificado específico.</p>
	 * <p>Busca en primer lugar el primer alias que coincide con el certificado, si no tiene clave asociada pasa a buscar por todos los
	 * alias del almacén cuál tiene clave privada y de ellos busca el certificado que coincida con el provisto.</p>
	 * <p>Utiliza como contraseña
	 * @param ks Keystore con las claves y certificados
	 * @param certificate Certificado del que se quiere su clave privada
	 * @param passHandler manejador de las contraseñas
	 * @return Clave privada
	 * @throws CertStoreException Lanzada cuando no consigue acceso a la clave por los siguientes motivos:
	 * 			<ul>
	 * 				<li>fallo de contraseña</li>
	 * 				<li>ausencia de certificado en el keystore</li>
	 * 				<li>ausencia de clave (está el certificado pero no tiene clave asociada, es un TrustedCertificate)</li>
	 * 			</ul>
	 * @see es.mityc.javsign.pkstore.keystore.KeyTool#findPrivateKey
	 */
	public static PrivateKey findPrivateKey(final KeyStore ks, final X509Certificate certificate, final IPassStoreKS passHandler) throws CertStoreException {
		return findPrivateKey(ks, certificate, passHandler, EMPTY_STRING);
	}

	/**
	 * <p>Recupera los certificados de confianza contenidos en el KeyStore.</p>
	 * @param ks Almacén de certificados
	 * @return Listado de certificados de confianza
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con el KeyStore interno
	 */
	public static List<X509Certificate> getTrustCertificates(final KeyStore ks) throws CertStoreException {
		try {
			Enumeration<String>total = ks.aliases();
			ArrayList<X509Certificate>lista = new ArrayList<X509Certificate>();
			while (total.hasMoreElements()) {
				String alias = total.nextElement();
				if ((ks.isCertificateEntry(alias)) && (!ks.isKeyEntry(alias))) {
					Certificate cert = ks.getCertificate(alias);
					if (cert instanceof X509Certificate) {
						lista.add((X509Certificate) cert);
					}
				}
			}
			return lista;
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_KS_1, ex.getMessage(), ex));	
		}
	}


	
	/**
	 * <p>Constructor oculto.</p>
	 */
	private KeyTool() { }

}
