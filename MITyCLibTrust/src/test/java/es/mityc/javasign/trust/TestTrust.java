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

import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Vector;

import org.junit.Test;

import es.mityc.javasign.trust.PropsTruster.TrusterType;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;


/**
 * <p>Test de los managers de completa confianza y completa desconfianza.</p>
 * 
 */
public class TestTrust {
	
	/** Managers de completa confianza. */
	private static final String PREFIX_ALL_TRUSTED = "alltrusted";
	/** Managers de completa desconfianza. */
	private static final String PREFIX_ALL_UNTRUSTED = "alluntrusted";
	/** Manager de confianza parcial. */
	private static final String PREFIX_MITYC_TRUSTED = "test";
	/** CRL de pruebas. */
	private static final String RES_CRL_IAIK = "/samples/IAIK CaRA-DEMO CA.crl";
	
	/**
	 * Obtiene la factoría extendida.
	 * @return Factoría extendida
	 */
	private TrustExtendFactory getExtendFactory() {
		TrustFactory tf = TrustFactory.getInstance();
		if ((tf == null) || (!(tf instanceof TrustExtendFactory))) {
			fail("Factoría de Trust no es Extend");
		}
		return (TrustExtendFactory) tf;
	}
	
	/**
	 * <p>Comprueba que se puede acceder a la factoría extendida.</p>
	 */
	@Test
	public void testExtendFactory() {
		getExtendFactory();
	}
	
	/**
	 * <p>Comprueba que se confía en una CRL de prueba.</p>
	 */
	@Test
	public void testCRLAllTrusted() {
		TrustExtendFactory tef = getExtendFactory();
		ITrustCRLEmisor crlTrust = tef.getCRLTruster(PREFIX_ALL_TRUSTED);
		assertNotNull("Validador de confianza es nulo", crlTrust);
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			X509CRL crl = (X509CRL) cf.generateCRL(this.getClass().getResourceAsStream(RES_CRL_IAIK));
			crlTrust.isTrusted(crl);
		} catch (CertificateException ex) {
			fail("No se puede generar CRL de pruebas: " + ex.getMessage());
		} catch (CRLException ex) {
			fail("No se puede generar CRL de pruebas: " + ex.getMessage());
		} catch (NotTrustedException ex) {
			fail("Se ha marcado la crl como de no confianza");
		} catch (UnknownTrustException ex) {
			fail("Se ha marcado la crl como de confianza desconocida");
		} catch (TrustException ex) {
			fail("Error al comprobar la confianza de la CRL: " + ex.getMessage());
		}
	}
	
	/**
	 * <p>Comprueba que no se confía en una CRL de prueba.</p>
	 */
	@Test
	public void testCRLAllUntrusted() {
		TrustExtendFactory tef = getExtendFactory();
		ITrustCRLEmisor crlTrust = tef.getCRLTruster(PREFIX_ALL_UNTRUSTED);
		assertNotNull("Validador de confianza es nulo", crlTrust);
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			X509CRL crl = (X509CRL) cf.generateCRL(this.getClass().getResourceAsStream(RES_CRL_IAIK));
			crlTrust.isTrusted(crl);
			fail("CRL debería marcarse como de no confianza");
		} catch (CertificateException ex) {
			fail("No se puede generar CRL de pruebas: " + ex.getMessage());
		} catch (CRLException ex) {
			fail("No se puede generar CRL de pruebas: " + ex.getMessage());
		} catch (NotTrustedException ex) {
		} catch (UnknownTrustException ex) {
			fail("Se ha marcado la crl como de confianza desconocida");
		} catch (TrustException ex) {
			fail("Error al comprobar la confianza de la CRL: " + ex.getMessage());
		}
	}
	
	/**
	 * <p>Comprueba que se pueda incluir una CA al mecanismo de confianza.</p>
	 */
	@Test
	public void testAddCA() {
		
		CertPath cp = null;
		X509Certificate certIssuer = null;
		X509Certificate certRaiz = null;
		CertificateFactory cf = null;
		
		// Se cargan los certificados a probar
		try {
			cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(this.getClass().getResourceAsStream("/trust/certs/cert.cer"));
			certIssuer = (X509Certificate) cf.generateCertificate(this.getClass().getResourceAsStream("/trust/certs/issuers/causr.cer"));
			certRaiz = (X509Certificate) cf.generateCertificate(this.getClass().getResourceAsStream("/trust/certs/issuers/cacert.cer"));
			
			// Se genera la cadena
			Vector<X509Certificate> certs = new Vector<X509Certificate>();			
			certs.add(cert);
			certs.add(certIssuer);
			certs.add(certRaiz);
			cp = cf.generateCertPath(certs);
		} catch (CertificateException ex) {
			fail("No se pudo cargar la cadena de certificados: " + ex.getMessage());
		}
		
		TrusterType type = TrusterType.TRUSTER_SIGNCERTS_ISSUER;
		
		MyPropsTruster.getInstance(this.getClass().getResourceAsStream("/trust/testTruster.properties"));
		
		TrustExtendFactory tef = getExtendFactory();
		MyPropsTruster truster = (MyPropsTruster) tef.getTruster(PREFIX_MITYC_TRUSTED);
		
		try {
			truster.addCA(certIssuer, type, System.getProperty("java.io.tmpdir"));
			truster.addCA(certRaiz, type, System.getProperty("java.io.tmpdir"));
		} catch (TrustException e) {
			fail("Error al incluir una nueva CA de usuario: " + e.getMessage());
		}
		
		ITrustSignCerts signTrust = (ITrustSignCerts) truster;
		assertNotNull("Validador de confianza es nulo", signTrust);
		try {
			signTrust.isTrusted(cp);
		} catch (NotTrustedException ex) {
			fail("Se ha marcado el certificado incluido como de no confianza");
		} catch (UnknownTrustException ex) {
			fail("Se ha marcado el certificado incluido como de confianza desconocida");
		} catch (TrustException ex) {
			fail("Error al comprobar la confianza del certificado incluido: " + ex.getMessage());
		}
	}
	
	/**
	 * <p>Comprueba que se reconstruya bien la ruta de certificación de una PKI de pruebas.</p>
	 */
	@Test
	public void testGetCertPath() {
		
		// Se carga el certificado a probar
		X509Certificate cert = null;
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) cf.generateCertificate(this.getClass().getResourceAsStream("/trust/certs/cert.cer"));
		} catch (CertificateException ex) {
			fail("No se pudo cargar el certificado: " + ex.getMessage());
		}
		
		TrustExtendFactory tef = getExtendFactory();
		TrustAbstract truster = tef.getTruster(PREFIX_MITYC_TRUSTED);
		
		CertPath cp = null;
		try {
			cp = truster.getCertPath(cert);
		} catch (TrustException e) {
			fail("Error al construir la cadena: " + e.getMessage());
		}
		
		assertNotNull("La cadena generada es nula", cp);
		
		if (cp.getCertificates().size() != 3) {
			fail("La cadena no esta completa");
		}
	}
}
