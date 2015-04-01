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
package es.mityc.crypto.examples;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import es.mityc.crypto.asymetric.RSAManager;
import es.mityc.javasign.ConstantsAPI;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KSStore;
import es.mityc.javasign.pkstore.keystore.PassStoreKS;



public class RSAEncryption extends GenericEncryption {
	
	private static final String PATH_PUBLIC_CERT="/keystores/usr0061.cer";
	private static final String PATH_PRIVATE_CERT="/keystores/usr0061.p12";
	private static final String CERT_PASSWORD = "usr0061";
	private static final String ALGORITMO =RSAManager.RSA_ECB_PKCS1;
	
	private static final String PROVEEDOR = ConstantsAPI.PROVIDER_BC_NAME;
//	private static final String PROVEEDOR = null;
	
	@Override
	protected char[] encrypt(String cadena) {
		X509Certificate cert = null;
		if (PATH_PUBLIC_CERT.endsWith("cer") || PATH_PUBLIC_CERT.endsWith("crt")) {
			try {
				CertificateFactory cfTemporal = CertificateFactory.getInstance("X.509");	
				cert = (X509Certificate) cfTemporal.generateCertificate(this.getClass().getResourceAsStream(PATH_PUBLIC_CERT));
			} catch (Exception e) {
				System.out.println("Error al recuperar el certificado.- " + e.getMessage());
				return null;
			}
		}
		
		
		RSAManager rsa = new RSAManager();
		rsa.feedSeed(SecureRandom.getSeed(8));
		
		return rsa.protectRSA(DATA_TO_ENCRYPT.getBytes(), cert.getPublicKey(), ALGORITMO,Security.getProvider(PROVEEDOR));
	}

	@Override
	protected String decrypt(char[] cadena) {
		
        // Obtencion del gestor de claves
        IPKStoreManager storeManager = getPKStoreManager();
        if (storeManager == null) {
            System.err.println("El gestor de claves no se ha obtenido correctamente.");
            return null;
        }

        // Obtencion del certificado para descifrar. Utilizaremos el primer
        // certificado del almacen.
        X509Certificate certificate = getFirstCertificate(storeManager);
        if (certificate == null) {
            System.err.println("No existe ningún certificado para firmar.");
            return null;
        }

		RSAManager rsa = new RSAManager();
		return new String(rsa.recoverRSA(cadena, storeManager,certificate,ALGORITMO,Security.getProvider(PROVEEDOR)));
	}

	/**
     * <p>
     * Devuelve el gestor de claves que se va a utilizar
     * </p>
     * 
     * @return El gestor de claves que se va a utilizar</p>
     */
    private IPKStoreManager getPKStoreManager() {
        IPKStoreManager storeManager = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(this.getClass().getResourceAsStream(PATH_PRIVATE_CERT), CERT_PASSWORD.toCharArray());
            storeManager = new KSStore(ks, new PassStoreKS(CERT_PASSWORD));
        } catch (KeyStoreException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (CertificateException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        }
        return storeManager;
    }
    /**
     * <p>
     * Recupera el primero de los certificados del almacén.
     * </p>
     * 
     * @param storeManager
     *            Interfaz de acceso al almacén
     * @return Primer certificado disponible en el almacén
     */
    private X509Certificate getFirstCertificate(
            final IPKStoreManager storeManager) {
        List<X509Certificate> certs = null;
        try {
            certs = storeManager.getSignCertificates();
        } catch (CertStoreException ex) {
            System.err.println("Fallo obteniendo listado de certificados");
            System.exit(-1);
        }
        if ((certs == null) || (certs.size() == 0)) {
            System.err.println("Lista de certificados vacía");
            System.exit(-1);
        }

        X509Certificate certificate = certs.get(0);
        return certificate;
    }

    /**
	 * @param args
	 */
	public static void main(String[] args) {
		RSAEncryption rsaEnc = new RSAEncryption();
		rsaEnc.execute();
	}

}
