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
package es.mityc.javasign.issues;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;

import es.mityc.firmaJava.ValidationBase;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.bridge.SigningException;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KSStore;
import es.mityc.javasign.xml.refs.AllXMLToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * <p>Prueba de Issue #299.</p>
 * <p>Error en firma de XML con nodo de estilo.</p>
 * 
 */
public class Test299 extends ValidationBase {
	
	private IPKStoreManager getPKStore() {
		IPKStoreManager pks = null;
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(this.getClass().getResourceAsStream("/issues/299/usr0061.p12"), "usr0061".toCharArray());
			pks = new KSStore(ks, new PassStoreKS("usr0061"));
		} catch (KeyStoreException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		} catch (NoSuchAlgorithmException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		} catch (CertificateException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		} catch (IOException ex) {
			fail("No se puede generar KeyStore JKS: " + ex.getMessage());
		}
		return pks;
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
		
		X509Certificate certificate = certs.get(0);
		assertNotNull("El primer certificado del almacén no existe", certificate);
		return certificate;
	}

	
	@Test
	public void test() {
		try {
			Document doc = loadDoc("/issues/299/299.xml");
			
			IPKStoreManager iStore = getPKStore();
			X509Certificate cert = getCertificate(iStore);

			DataToSign data2Sign = new DataToSign();
			data2Sign.setDocument(doc);
			data2Sign.addObject(new ObjectToSign(new AllXMLToSign(), null, null, null, null));
			
			data2Sign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
			data2Sign.setEsquema(XAdESSchemas.XAdES_132);
			data2Sign.setEnveloped(true);

		    try {
		    	FirmaXML firma = new FirmaXML();
		    	Object[] res = firma.signFile(cert, data2Sign, iStore.getPrivateKey(cert), iStore.getProvider(cert));
		    	doc = (Document) res[0];
			} catch (Exception ex) {
				throw new SigningException("Error realizando la firma", ex);
			}
			
			// valida la firma recién hecha
			if (!validateDoc(doc, null, null)) {
				Assert.fail("La firma realizada en el test #299 debería ser válida");
			}
		} catch (Throwable th) {
			LOGGER.info(th.getMessage());
			LOGGER.info("", th);
			Assert.fail("Error en test #299: " + th.getMessage());
		}
	}

}
