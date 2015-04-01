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
package es.mityc.javasign.pkstore;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;


/**
 * <p>Funcionalidad básica para los tests de acceso a los store.</p>
 * 
 */
public class StoreTests {

	/** Tamaño en bytes del búffer de datos que se firmará. */
	protected static final int SIZE_BUFFER = 25;
	/** Valor modular máximo que puede tener el contenido aleatorio generado para firmar. */
	protected static final int BYTE_UNSIGNED_SIZE = 256;
	
	/** Filtro para seleccionar el certificado a utilizar. */
	protected static X509CertSelector certSelector = null;
	
	/**
	 * <p>Establece un filtro de certificados.</p>
	 * @param selector Selector de certificados, <code>null</code> si se quiere el primer certificado encontrado
	 */
	protected static void setFilter(final X509CertSelector selector) {
		certSelector = selector;
	}
	
	/**
	 * <p>Carga un certificado disponible en un stream de entrada.</p>
	 * @param is Stream de entrada
	 * @return certificado X509 que hay disponible, <code>null</code> si no encuentra un certificado
	 */
	protected static X509Certificate loadCertificate(final InputStream is) {
		X509Certificate cert = null;
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			cert = (X509Certificate) cf.generateCertificate(is);
		} catch (CertificateException ex) {
			fail("No se puede acceder a la factoría de certificados X.509: " + ex.getMessage());
		} catch (ClassCastException ex) {
			fail("El objeto indicado no es un objeto X509Certificate: " + ex.getMessage());
		}
		return cert;
	}
	
	/**
	 * <p>Recupera el primero de los certificados del almacén.</p>
	 * @param sm Interfaz de acceso al almacén
	 * @return Primer certificado disponible en el almacén
	 */
	protected X509Certificate getCertificate(final IPKStoreManager sm) {
		List<X509Certificate> certs = null;
		try {
			certs = sm.getSignCertificates();
		} catch (CertStoreException ex) {
			fail("Fallo obteniendo listado de certificados");
		}
		if ((certs == null) || (certs.size() == 0)) {
			fail("Lista de certificados vacía");
		}
		
		X509Certificate certificate = null;
		if (certSelector != null) {
			Iterator<X509Certificate> itCert = certs.iterator();
			while (itCert.hasNext()) {
				X509Certificate certTemp = itCert.next(); 
				if (certSelector.match(certTemp)) {
					certificate = certTemp;
					break;
				}
			}
//			if (certificate == null) {
//				fail("No se ha encontrado un certificado que se ajustase al criterio del filtro.");
//			}
		} else {
			certificate = certs.get(0);
		}
		return certificate;
	}
	
	/**
	 * <p>Comprueba que se puede firmar utilizando el primer certificado del almacén.</p>
	 * @param sm Almacén que contiene el certificado para firmar
	 */
	protected void checkSign(final IPKStoreManager sm) {
		X509Certificate cert = getCertificate(sm);
		if (cert == null) {
			fail("No se pudo obtener un certificado del almacén");
		}
		Provider provider = sm.getProvider(cert);
		
		// Datos a firmar/verificar: genera un buffer con datos
		byte[] data = new byte[SIZE_BUFFER];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) (i % BYTE_UNSIGNED_SIZE);
		}
		byte[] resultado = null;
		
		// Firma un conjunto de datos
		try {
			Signature sig = Signature.getInstance("SHA1withRSA", provider);
			sig.initSign(sm.getPrivateKey(cert));
			sig.update(data);
			resultado = sig.sign();
		} catch (NoSuchAlgorithmException ex) {
			fail("No se ha encontrado algoritmo para firmar con RSA");
		} catch (InvalidKeyException ex) {
			fail("La clave privada/certificado indicado no es comprendida por este engine de firma");
		} catch (CertStoreException ex) {
			fail("Error obteniendo clave privada asociada a certificado");
		} catch (SignatureException ex) {
			fail("Error obteniendo firma");
		}

 		// Comprueba que la firma es correcta mediante el validador general
		try {
			Signature sig = Signature.getInstance("SHA1withRSA"/*, "SunRsaSign"*/);
			sig.initVerify(cert.getPublicKey());
			sig.update(data);
			if (!sig.verify(resultado)) {
				fail("La firma no coincide con el certificado firmante");
			}
		} catch (NoSuchAlgorithmException ex) {
			fail("No se ha encontrado algoritmo para firmar con RSA: " + ex.getMessage());
		} catch (InvalidKeyException ex) {
			fail("La clave privada/certificado indicado no es válida para este engine de firma: " + ex.getMessage());
		} catch (SignatureException ex) {
			fail("Error verificando firma: " + ex.getMessage());
//		} catch (NoSuchProviderException ex) {
//			fail("No se ha encontrado el proveedor para comprobar la firma");
		}
	}
	
    /**
     * <p>Lista los certificados del almacén en un flujo de salida.</p>
     * @param sm Almacén que contiene los certificados
     * @param outputStream Flujo donde se desea escribir el listado
     */
    public void listSignCertificates(final IPKStoreManager sm, OutputStream outputStream) {
        try {
            List<X509Certificate> certs = sm.getSignCertificates();
            Iterator<X509Certificate> itCerts = certs.iterator();
            while (itCerts.hasNext()) {
                X509Certificate certificate = (X509Certificate) itCerts.next();
                printCertificate(certificate, outputStream);
            }
        } catch (CertStoreException e) {
            fail("Etrror listando los certificados de firma");
        } catch (IOException e) {
            fail("Etrror escribiendo los certificados al flujo de salida");
        }
    }

    /**
     * <p>Lista los certificados del almacén en un flujo de salida.</p>
     * @param sm Almacén que contiene los certificados
     * @param outputStream Flujo donde se desea escribir el listado
     */
    public void listTrustCertificates(final IPKStoreManager sm, OutputStream outputStream) {
        try {
            List<X509Certificate> certs = sm.getTrustCertificates();
            Iterator<X509Certificate> itCerts = certs.iterator();
            while (itCerts.hasNext()) {
                X509Certificate certificate = (X509Certificate) itCerts.next();
                printCertificate(certificate, outputStream);
            }
        } catch (CertStoreException e) {
            fail("Etrror listando los certificados de firma");
        } catch (IOException e) {
            fail("Etrror escribiendo los certificados al flujo de salida");
        }
    }

    /**
     * <p> Imprime un certificado por un flujo de salida
     * @param certificate El certificado a imprimir
     * @param outputStream Flujo donde se desea escribir
     * @throws IOException Si ocurre algún error de entrada/salida
     */
    private void printCertificate(X509Certificate certificate, OutputStream outputStream) throws IOException {
        StringBuffer certificateInfo = new StringBuffer();
        certificateInfo.append("Enviado a: [").append(certificate.getSubjectDN()).append("] ");
        certificateInfo.append(", Emitido por: [").append(certificate.getIssuerDN()).append("] ");
        certificateInfo.append(", Nº serie: [").append(certificate.getSerialNumber()).append("] ");
        certificateInfo.append(", Fecha caducidad: [").append(certificate.getNotAfter()).append("]\n");
        outputStream.write(certificateInfo.toString().getBytes());
    }
}
