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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>Gestiona las entidades de confianza que admite MITyC.</p>
 * <p>Esta clase se basa en ficheros de configuración para parametrizar los certificados admitidos (en /trust/mitycsimple.properties).</p>
 * 
 */
public class MyPropsTruster extends PropsTruster implements ITrustServices {
	
	static Log log = LogFactory.getLog(MyPropsTruster.class);

	/** Nombre del fichero de configuración interno. */
	private static final String CONF_FILE = "trust/myTruster.properties";
	
	/** Instancia única del tipo de manager interno de confianza. */
    //private static MyPropsTruster instance;

	/**
	 * <p>Constructor.</p>
	 */
	protected MyPropsTruster(InputStream externalConf) {
		super(CONF_FILE, externalConf);
	}
	
	/**
	 * <p>Devuelve una instancia única del gestionador de confianza propio.</p>
	 * @param ruta al fichero de configuración de confianza externo  
	 * @return Instancia de este gestionador de confianza
	 */
	public static synchronized MyPropsTruster getInstance(InputStream externalConf) {
		if (instance == null) {
			instance = new MyPropsTruster(externalConf);
		}
		return (MyPropsTruster)instance;
	}
	
	/**
	 * <p>Vuelve a cargar los properties de gestión de confianza.</p> 
	 */
	private synchronized void reloadConf() {
		loadConf(CONF_FILE, externalProps);
	}

	/**
	 * <p>Permite incluir un certificado en el repositorio de usuario indicado.<p>
	 * @param cert Certificado a incluir.
	 * @param type Tipo de certificado.
	 * @param path Ruta física al repositorio
	 * @see es.mityc.javasign.trust.PropsTruster.TrusterType
	 */
	public void addCA(X509Certificate cert, TrusterType type, String path) throws TrustException {
		String fileName = null;

		List<TrustCertStruct> cas = getCAs();
		for (int i = 0; i < cas.size(); ++i) {
			if (cert.equals(cas.get(i).getCert())) {
				return;
			}
		}

		// Se calcula el valor de Digest del certificado
		try {
			fileName = Utils.getMD5(cert);
		} catch (Exception e) {
			throw new TrustException(e);
		}

		// Se guarda el certificado en una ubicación específica, a partir del Path indicado
		String pathToCert = path + File.separator + "CAs";
		// Si el directorio destino no existe, se crea
		File desFile = new File(pathToCert);
		if (!desFile.exists()) {
			desFile.mkdirs();
		}
		
		// Se construye el destino del certificado
		pathToCert = path + File.separator + "CAs" + File.separator + fileName + ".cer";
		
		if (!new File(pathToCert).exists()) {
			// Se hace efectiva la escritura del certificado
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(pathToCert);
				fos.write(cert.getEncoded());
			} catch (IOException e) {
				throw new TrustException(e);
			} catch (CertificateEncodingException e) {
				throw new TrustException(e);
			} finally {
				if (fos != null) {
					try {
						fos.close();
					} catch (IOException e) { throw new TrustException(e); }
				}
			}
		}

		// Se modifica el fichero de propiedades para incluir la nueva referencia
		// Se calcula la Key correspondiente
		String key = type.toString() + '.' + fileName;
		for (int i = 2; externalProps.containsKey(key); ++i) {
			key = type.toString() + '.' + fileName + i;
		}

		// Se hace efectiva la inclusión
		externalProps.setProperty(key, pathToCert);

		// Se hacen efectivos los cambios
		reloadConf();
	}
	
	/**
	 * <p>Comprueba si la clave existe dentro de las propiedades externas cargadas.</p>
	 * @param md5Digest 
	 * @return
	 */
	public boolean containsCert(String md5Digest) throws TrustException {
		// Se cargan las propiedades si no lo estaban
		if (externalProps == null) {
			throw new TrustException("No hay propiedades externas cargadas");			
		} else {
			boolean result = false;
			Enumeration<?> keys = externalProps.keys();
			String key = null;
			while (keys.hasMoreElements()) {
				key = (String)keys.nextElement();
				if (key.contains(md5Digest)) {
					result = true;
					break;
				}
			}
			
			return result;
		}
	}
	
	/**
	 * <p>Permite borrar un certificado del repositorio del usuario.<p>
	 * @param cert Certificado a borrar.
	 * @param type Tipo de certificado.
	 * @param path Ruta física al repositorio
	 * @see es.mityc.javasign.trust.PropsTruster.TrusterType
	 */
	public void removeCA(X509Certificate cert, TrusterType type, String path) throws TrustException {
		// Se calcula el valor de Digest del certificado
		String fileName = null;
		try {
			fileName = Utils.getMD5(cert);
		} catch (Exception e) {
			throw new TrustException(e);
		}
		
		// Se borra el certificado de una ubicación específica, obtenida a partir del Path indicado
		String pathToCert = path + "CAs";
		// Si el directorio destino no existe, se lanza una excepción
		File desFile = new File(pathToCert);
		if (!desFile.exists()) {
			throw new TrustException("No se encuentra el repositorio de certificados local");
		}
		
		// Se construye el nombre del certificado
		pathToCert = pathToCert + File.separator + fileName + ".cer";

		// Se modifican las propiedades para excluir la referencia eliminando la Key correspondiente
		String keyToDel = type.toString() + '.' + fileName;
		boolean isDeleted = false;
		if (externalProps.containsKey(keyToDel)) {
			Enumeration<?> keys = externalProps.keys();
			String key = null;
			while (keys.hasMoreElements()) {
				key = (String)keys.nextElement();
				if (key.contains(keyToDel)) {
					// Se hace efectiva la exclusión
					externalProps.remove(key);
					isDeleted = true;
					break;
				}
			}

			if (isDeleted) {
				// Se toman en cuenta los cambios
				reloadConf();
			} else {
				throw new TrustException("Error al borrar. No se pudo borrar el certificado " + keyToDel);
			}
		} else {
			throw new TrustException("Error al borrar. No se encuentra el certificado " + keyToDel);
		}

		// Se hace efectivo el borrado del certificado
		desFile = new File(pathToCert);

		if (!desFile.exists()) {
			throw new TrustException("Error al borrar. No se encuentra el certificado indicado");
		} else {
			if (!desFile.delete()) {
				log.error("No se pudo borrar el certificado indicado: " + pathToCert);
				desFile.deleteOnExit();
			}
		}
	}

	/**
	 * <p>Parsea un nuevo fichero de propiedades y devuelve una lista con todas las
	 *  CAs de usuario configuradas.</p>
	 * @param path Ruta al fichero de configuración externo de usuario
	 * @return Lista de certificados configurada
	 * @throws TrustException En caso de error
	 */
	public List<TrustCertStruct> getCAs() throws TrustException {
		ArrayList<TrustCertStruct> cas = new ArrayList<TrustCertStruct>();
		
		// Propiedades internas		
		Iterator<X509Certificate> internalCAs = getTrustedCAs(TrusterType.TRUSTER_SIGNCERTS_CERTS).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_SIGNCERTS_CERTS, true));
		}
		internalCAs = getTrustedCAs(TrusterType.TRUSTER_SIGNCERTS_ISSUER).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_SIGNCERTS_ISSUER, true));
		}
		internalCAs = getTrustedCAs(TrusterType.TRUSTER_OCSP_CERTS).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_OCSP_CERTS, true));
		}
		internalCAs = getTrustedCAs(TrusterType.TRUSTER_OCSP_ISSUER).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_OCSP_ISSUER, true));
		}
		internalCAs = getTrustedCAs(TrusterType.TRUSTER_TSA_CERTS).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_TSA_CERTS, true));
		}
		internalCAs = getTrustedCAs(TrusterType.TRUSTER_TSA_ISSUER).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_TSA_ISSUER, true));
		}
		internalCAs = getTrustedCAs(TrusterType.TRUSTER_CRL_ISSUER).iterator();
		while (internalCAs.hasNext()) {
			cas.add(new TrustCertStruct(internalCAs.next(), TrusterType.TRUSTER_CRL_ISSUER, true));
		}

		// Propiedades externas
		if (externalProps == null || externalProps.size() <= 0) {
			return cas;
		}
		
		// Se listan todos los certificados
		Enumeration<?> keys = externalProps.keys();
		String key = null;
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new TrustException("Error al listar. No se pueden instanciar certificados X509", e);
		}
		FileInputStream fis = null;
		TrustCertStruct tc = null;
		while (keys.hasMoreElements()) {
			key = (String)keys.nextElement();
			try {
				tc = new TrustCertStruct();
				tc.setInternal(false);
				fis = new FileInputStream(new File(externalProps.getProperty(key)));
				X509Certificate  cert = (X509Certificate) cf.generateCertificate(fis);
				if (!checkCert(key, cert)) {
					throw new TrustException("Certificado alterado: " + key);
				}
				tc.setCert(cert);
				if (key.contains(TrusterType.TRUSTER_SIGNCERTS_CERTS.toString())) {
					tc.setType(TrusterType.TRUSTER_SIGNCERTS_CERTS);
				} else if (key.contains(TrusterType.TRUSTER_SIGNCERTS_ISSUER.toString())) {
					tc.setType(TrusterType.TRUSTER_SIGNCERTS_ISSUER);
				} else if (key.contains(TrusterType.TRUSTER_OCSP_CERTS.toString())) {
					tc.setType(TrusterType.TRUSTER_OCSP_CERTS);
				} else if (key.contains(TrusterType.TRUSTER_OCSP_ISSUER.toString())) {
					tc.setType(TrusterType.TRUSTER_OCSP_ISSUER);
				} else if (key.contains(TrusterType.TRUSTER_CRL_ISSUER.toString())) {
					tc.setType(TrusterType.TRUSTER_CRL_ISSUER);
				} else if (key.contains(TrusterType.TRUSTER_TSA_CERTS.toString())) {
					tc.setType(TrusterType.TRUSTER_TSA_CERTS);
				} else if (key.contains(TrusterType.TRUSTER_TSA_ISSUER.toString())) {
					tc.setType(TrusterType.TRUSTER_TSA_ISSUER);
				} else {
					tc.setType(TrusterType.TRUSTER_SIGNCERTS_CERTS);
				}
				boolean alreadyInList = false;
				for (int i = 0; i < cas.size(); ++i) {
					if (cas.get(i).getCert().equals(tc.getCert())) {
						tc.setInternal(false); // El almacén externo tiene prevalencia sobre el interno
						cas.remove(i);
						cas.add(i, tc);
						alreadyInList = true;
						break;
					}
				}
				if (!alreadyInList) {
					cas.add(tc);
				}
			} catch (CertificateException e) {
				log.error("Error al listar. No se pudo leer el certificado " + externalProps.getProperty(key), e);
			} catch (FileNotFoundException e) {
				log.error("Error al listar. No se pudo encontrar el certificado " + externalProps.getProperty(key), e);
			} finally {
				if (fis != null) {
					try {
						fis.close();
					} catch (IOException e) {}
				}
			}
		}

		return cas;
	}
	
	/**
	 * <p>Devuelve las propiedades externas teniendo en cuenta las nuevas modificaciones.</p>
	 * @return Propiedades externas modificadas
	 */
	public Properties getActualProperties() {
		return externalProps;
	}
	
	public class TrustCertStruct {
		/** Certificado. */
		private X509Certificate cert = null;
		/** Tipo de certificado. */
		private TrusterType type = null;
		/** Indica si es interno o externo. */
		private boolean isInternal = false;
		
		public TrustCertStruct() {
			new TrustCertStruct(null, null, false); 
		}
		
		public TrustCertStruct(X509Certificate cert, TrusterType type, boolean isInternal) {
			this.cert = cert;
			this.type = type;
			this.isInternal = isInternal;
		}
		
		public X509Certificate getCert() {
			return cert;
		}
		public synchronized void setCert(X509Certificate cert) {
			this.cert = cert;
		}
		public TrusterType getType() {
			return type;
		}
		public synchronized void setType(TrusterType type) {
			this.type = type;
		}
		public boolean isInternal() {
			return isInternal;
		}
		public void setInternal(boolean isInternal) {
			this.isInternal = isInternal;
		}
	}
	
	/**
	 * <p>Comprueba que el certificado no haya sido alterado.</p>
	 * @param key - Clave del certificado que contiene su Digest
	 * @param cert - Certificado a comparar
	 * @return <code>true</code> Si no se detecta cambio alguno.
	 * @throws TrustException
	 */
	private boolean checkCert(String key, X509Certificate cert) throws TrustException {
		// Se calcula el valor de Digest del certificado
		try {
			String fileName = Utils.getMD5(cert);
			return fileName == null? false : key.contains(fileName);
		} catch (Exception e) {
			throw new TrustException(e);
		}
	}
}
