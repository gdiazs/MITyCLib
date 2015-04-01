/*
 * Copyright 2005 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 */
package es.mityc.javasign.pkstore.mscapi.mityc;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.mityc.javasign.exception.CopyFileException;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.ConstantsCert;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.IPassStoreKS;
import es.mityc.javasign.pkstore.keystore.KeyTool;
import es.mityc.javasign.utils.CopyFilesTool;

/**
 * <p>Wrapper para permitir utilizar los servicios de MSCAPI (acceso a los servicios criptográficos de Microsoft en Windows) a través del
 * proveedor de seguridad SunMSCAPI-MITyC.</p> 
 * 
 */

public class MSCAPIMITyCStore implements IPKStoreManager {
	
    /** Localizaciones posibles de los almacenes. */
    public enum LocationStoreType { CurrentUser, LocalMachine };
    
	/** Internacionalizador. */
	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsCert.LIB_NAME);
	
    /** Nombre del almacén del usuario actual donde están los certificados personales. */
    private static final String MY_STORE = "Windows-MY";
    /** Nombre del almacén del usuario actual donde están los certificados de entidades raíz de confianza de windows. */
    private static final String ROOT_STORE = "Windows-ROOT";
    /** Nombre del almacén del usuario actual donde se encuentran las autoridades de certificación de windows. */
    private static final String CA_STORE = "Windows-CA";

    /** Nombre del almacén de la cuenta del equipo donde están los certificados personales. */
    private static final String LOCAL_MACHINE_MY_STORE = "Windows-LocalMachine-MY";
    /** Nombre del almacén de la cuenta del equipo donde están los certificados de entidades raíz de confianza de windows. */
    private static final String LOCAL_MACHINE_ROOT_STORE = "Windows-LocalMachine-ROOT";
    /** Nombre del almacén de la cuenta del equipo donde se encuentran las autoridades de certificación de windows. */
    private static final String LOCAL_MACHINE_CA_STORE = "Windows-LocalMachine-CA";

    /** Indica si la parte nativa se ha inicializado. */
	private static boolean initialized = false;
	
	/** Manejador de las contraseñas. */
	private IPassStoreKS passHandler;

    /** Localización del almacén. */
    private LocationStoreType locationStore;
    
	/**
	 * <p>PassHandler que no da acceso a ninguna contraseña.</p>
	 * 
	 */
	public class NullPassStorePK implements IPassStoreKS {
		/**
		 * <p>Devuelve una contraseña vacía en cualquier consulta.</p>
		 * @param certificate Certificado al que se accede
		 * @param alias alias al que se accede
		 * @return Contraseña vacía
		 * @see es.mityc.javasign.pkstore.IPassStoreKS#getPassword(java.security.cert.X509Certificate, java.lang.String)
		 */
		public char[] getPassword(final X509Certificate certificate, final String alias) {
			return new char[0];
		}
	}
	
    /**
     * <p>Copia la librería externa DLL al directorio temporal.</p>
     * @throws CopyFileException lanzada cuando no se puede copiar la librería nativa
     */
    private synchronized void copyLibrary() throws CopyFileException {
    	if (!initialized) {
			CopyFilesTool cft = new CopyFilesTool(ConstantsCert.CP_SUNMSCAPIMITYC_PROPERTIES, this.getClass().getClassLoader());
			cft.copyFilesOS(null, ConstantsCert.CP_SUNMSCAPIMITYC, true);
			initialized = true;
    	}
	}

    /**
     * <p>Constructor. Accederá al almacén del usuario actual.</p>
     * 
     * @param passStoreHandler Manejador que servirá para obtener acceso a certificados/claves de los almacenes de Windows. Si se indica
     *      <code>null</code> no se intentará utilizar ninguna contraseña al acceder a los almacenes.
     * @throws CertStoreException lanzada cuando no se puede acceder al almacén de windows mediante SunMSCAPI
     */
    public MSCAPIMITyCStore(final IPassStoreKS passStoreHandler) throws CertStoreException {
        this(passStoreHandler, LocationStoreType.CurrentUser);
    }
    
    /**
     * <p>Constructor indicando la localización del almacén.</p>
     * 
     * @param passStoreHandler Manejador que servirá para obtener acceso a certificados/claves de los almacenes de Windows. Si se indica
     *      <code>null</code> no se intentará utilizar ninguna contraseña al acceder a los almacenes.
     * @param location Localizacion del almacén
     * @throws CertStoreException lanzada cuando no se puede acceder al almacén de windows mediante SunMSCAPI
     */
    public MSCAPIMITyCStore(final IPassStoreKS passStoreHandler, LocationStoreType location) throws CertStoreException {
        this.locationStore = location;
		try {
			copyLibrary();
		} catch (CopyFileException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPIMITYC_1), ex);
		}
		if (passStoreHandler == null) {
			this.passHandler = new NullPassStorePK();
		} else {
			this.passHandler = passStoreHandler;
		}
	}

	/**
	 * <p>Obtiene la cadena de certificados asociada a un certificado específico.</p>
	 * <p>No implementado</p>
	 * @param certificate Certificado del que se requiere la cadena
	 * @return Lanza la excepción UnsupportedOperationException
	 * @throws CertStoreException No se lanza nunca
	 */
	public CertPath getCertPath(final X509Certificate certificate) throws CertStoreException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>Obtiene acceso a la clave privada de un certificado específico.</p>
	 * 
	 * @param certificate Certificado del que se quiere su clave privada
	 * @return Clave privada
	 * @throws CertStoreException Lanzada cuando no consigue acceso a la clave por los siguientes motivos:
	 * 			<ul>
	 * 				<li>fallo de contraseña</li>
	 * 				<li>ausencia de certificado en el keystore</li>
	 * 				<li>ausencia de clave (está el certificado pero no tiene clave asociada, es un TrustedCertificate)</li>
	 * 			</ul>
	 */
	public PrivateKey getPrivateKey(final X509Certificate certificate) throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
            case CurrentUser:
                storeName = MY_STORE;
                break;
            case LocalMachine:
                storeName = LOCAL_MACHINE_MY_STORE;
            default:
                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, new SunMSCAPI_MITyC());
			ks.load(null, null);
			PrivateKey resultado = KeyTool.findPrivateKey(ks, certificate, passHandler);
			return resultado;
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}

	/**
	 * <p>Devuelve el Provider que permite trabajar con los servicios criptográficos de MSCAPI.</p>
     * @param certificate Certificado para el que se necesita acceso al provider
	 * @return Provider asociado al MSCAPI
	 */
	public Provider getProvider(final X509Certificate certificate) {
		return new SunMSCAPI_MITyC();
	}

	/**
	 * <p>Recupera los certificados que pueden firmar contenidos disponibles según MSCAPI.</p>
	 * 
	 * @return Listado de certificados con clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con MSCAPI
	 */
	public List<X509Certificate> getSignCertificates() throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
            case CurrentUser:
                storeName = MY_STORE;
                break;
            case LocalMachine:
                storeName = LOCAL_MACHINE_MY_STORE;
            default:
                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, new SunMSCAPI_MITyC());
			ks.load(null, null);
			return KeyTool.getCertificatesWithKeys(ks);
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}

	/**
	 * <p>Recupera los certificados de confianza según MSCAPI. Los certificados serán la suma
     * de los existentes en los almacenes ROOT y CA.</p>
	 * @return Listado de certificados de confianza
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con MSCAPI
	 */
	public List<X509Certificate> getTrustCertificates() throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
	            case CurrentUser:
	                storeName = ROOT_STORE;
	                break;
	            case LocalMachine:
	                storeName = LOCAL_MACHINE_ROOT_STORE;
	            default:
	                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, new SunMSCAPI_MITyC());
			ks.load(null, null);
			ArrayList<X509Certificate> lista = new ArrayList<X509Certificate>();
			lista.addAll(KeyTool.getTrustCertificates(ks));

			switch (this.locationStore) {
	            case CurrentUser:
	                storeName = CA_STORE;
	                break;
	            case LocalMachine:
	                storeName = LOCAL_MACHINE_CA_STORE;
	            default:
	                break;
            }
            ks = KeyStore.getInstance(storeName, new SunMSCAPI_MITyC());
            ks.load(null, null);
			lista.addAll(KeyTool.getTrustCertificates(ks));
			return lista;
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}
	
	/**
	 * <p>Recupera los certificados públicos contenidos disponibles según MSCAPI.</p>
	 * 
	 * @return Listado de certificados sin clave privada
	 * @throws CertStoreException devuelta si hay algún problema en la comunicación con MSCAPI
	 */
	public List<X509Certificate> getPublicCertificates() throws CertStoreException {
		try {
            String storeName = null;
            switch (this.locationStore) {
            case CurrentUser:
                storeName = MY_STORE;
                break;
            case LocalMachine:
                storeName = LOCAL_MACHINE_MY_STORE;
            default:
                break;
            }
			KeyStore ks = KeyStore.getInstance(storeName, new SunMSCAPI_MITyC());
			ks.load(null, null);
			return KeyTool.getCertificatesWithoutKeys(ks);
		} catch (KeyStoreException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_1, ex.getMessage(), ex));
		} catch (NoSuchAlgorithmException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_2, ex.getMessage(), ex));
		} catch (CertificateException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_3, ex.getMessage(), ex));
		} catch (IOException ex) {
			throw new CertStoreException(I18N.getLocalMessage(ConstantsCert.I18N_CERT_MSCAPI_4, ex.getMessage(), ex));
		}
	}
}
