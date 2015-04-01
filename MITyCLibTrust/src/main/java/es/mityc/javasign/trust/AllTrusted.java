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

import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * <p>Manager de absoluta confianza.</p>
 * <p>Se da por válidos todos los elementos. Clase de test.</p>
 * 
 */
public final class AllTrusted extends TrustAdapter {
	
	/** Instancia única del manager de confianza. */
	private static AllTrusted instance = new AllTrusted();

	/**
	 * <p>Da como válida la CRL.</p>
	 * @param crl CRL
	 * @throws TrustException Nunca se lanza
	 * @see es.mityc.javasign.trust.ITrustCRLEmisor#isTrusted(java.security.cert.X509CRL)
	 */
	public void isTrusted(final X509CRL crl) throws TrustException {
	}

	/**
	 * <p>Da como válida la respuesta OCSP.</p>
	 * @param ocsp Respuesta OCSP
	 * @throws TrustException Nunca se lanza
	 * @see es.mityc.javasign.trust.ITrustOCSPProducer#isTrusted(org.bouncycastle.ocsp.OCSPResp)
	 */
	public void isTrusted(final OCSPResp ocsp) throws TrustException {
	}

	/**
	 * <p>Da como válida la cadena de certificación.</p>
	 * @param certs Cadena de certificados
	 * @throws TrustException Nunca se lanza
	 * @see es.mityc.javasign.trust.ITrustSignCerts#isTrusted(java.security.cert.CertPath)
	 */
	public void isTrusted(final CertPath certs) throws TrustException {
	}

	/**
	 * <p>Da como válido el sello de tiempo.</p>
	 * @param tst Sello de tiempo
	 * @throws TrustException Nunca se lanza
	 * @see es.mityc.javasign.trust.ITrustTSProducer#isTrusted(org.bouncycastle.tsp.TimeStampToken)
	 */
	public void isTrusted(final TimeStampToken tst) throws TrustException {
	}

	/**
	 * <p>Devuelve una instancia única del manager.</p>
	 * <p>Este clase se puede utilizar sin protección de sincronismo.</p>
	 * @return Instancia única del manager
	 */
	public static TrustAbstract getInstance() {
		return instance;
	}
	
	/**
	 * <p>Devuelve una cadena de certificados que contiene únicamente el certificado introducido.</p>
	 */
	@Override
	public CertPath getCertPath(X509Certificate cert) throws UnknownTrustException {
		
		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
		list.add(cert);
		
		CertPath certPath = null;
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			certPath = cf.generateCertPath(list);
		} catch (CertificateException e) {
			throw new UnknownTrustException(e.getMessage(), e);
		}
		
		return certPath;
	}
}
