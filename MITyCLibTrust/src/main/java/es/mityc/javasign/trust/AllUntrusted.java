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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * <p>Manager de absoluta desconfianza.</p>
 * <p>Se da por inválidos todos los elementos. Clase de test.</p>
 * 
 */
public final class AllUntrusted extends TrustAdapter {

	/** Instancia única del manager de confianza. */
	private static AllUntrusted instance = new AllUntrusted();

	/**
	 * <p>Da como inválida la CRL.</p>
	 * @param crl CRL
	 * @throws TrustException siempre se lanza NotTrustedException
	 * @see es.mityc.javasign.trust.ITrustCRLEmisor#isTrusted(java.security.cert.X509CRL)
	 */
	public void isTrusted(final X509CRL crl) throws TrustException {
		throw new NotTrustedException();
	}

	/**
	 * <p>Da como inválida la respuesta OCSP.</p>
	 * @param ocsp Respuesta OCSP
	 * @throws TrustException siempre se lanza NotTrustedException
	 * @see es.mityc.javasign.trust.ITrustOCSPProducer#isTrusted(org.bouncycastle.ocsp.OCSPResp)
	 */
	public void isTrusted(final OCSPResp ocsp) throws TrustException {
		throw new NotTrustedException();
	}

	/**
	 * <p>Da como inválida la cadena de certificados.</p>
	 * @param certs Cadena de certificados
	 * @throws TrustException siempre se lanza NotTrustedException
	 * @see es.mityc.javasign.trust.ITrustSignCerts#isTrusted(java.security.cert.CertPath)
	 */
	public void isTrusted(final CertPath certs) throws TrustException {
		throw new NotTrustedException();
	}

	/**
	 * <p>Da como inválido el sello de tiempo.</p>
	 * @param tst Sello de tiempo
	 * @throws TrustException siempre se lanza NotTrustedException
	 * @see es.mityc.javasign.trust.ITrustTSProducer#isTrusted(org.bouncycastle.tsp.TimeStampToken)
	 */
	public void isTrusted(final TimeStampToken tst) throws TrustException {
		throw new NotTrustedException();
	}

	/**
	 * <p>Devuelve una instancia única del manager.</p>
	 * <p>Este clase se puede utilizar sin protección de sincronismo.</p>
	 * @return Instancia única del manager
	 */
	public static TrustAbstract getInstance() {
		return instance;
	}

	@Override
	public CertPath getCertPath(X509Certificate cert) throws UnknownTrustException {
		throw new UnknownTrustException("Not implemented");
	}
}
