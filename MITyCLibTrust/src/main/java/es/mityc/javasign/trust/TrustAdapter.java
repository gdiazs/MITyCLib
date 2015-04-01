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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * <p>Clase base que redirige las peticiones de un manager que sigue {@link TrustAbstract} a uno de la factoría extendidad que implemente los
 * interfaces propios.</p>
 * 
 */
public abstract class TrustAdapter extends TrustAbstract implements ITrustCRLEmisor,
		ITrustOCSPProducer, ITrustSignCerts, ITrustTSProducer {
	
	private static Log logger = LogFactory.getLog(TrustAdapter.class);

	/**
	 * <p>Discrimina en función del tipo de objeto qué método hay que lanzar de la clase que lo extienda.</p>
	 * <p>Discrimina entre los objetos: cadena de certificados, sello de tiempo, CRL y respuesta OCSP.</p>
	 * @param data objeto del que hay que comprobar su confianza
	 * @throws TrustException Lanzada cuando no se confía en el elemento. Lanza una de tipo UnknownTrustException cuando no se reconoce el tipo de objeto
	 * @see es.mityc.javasign.trust.TrustAbstract#isTrusted(java.lang.Object)
	 */
	@Override
	public void isTrusted(final Object data) throws TrustException {
		if (data instanceof CertPath) {
			isTrusted((CertPath) data);
		} else if (data instanceof TimeStampToken) {
			isTrusted((TimeStampToken) data);
		} else if (data instanceof X509CRL) {
			isTrusted((X509CRL) data);
		} else if (data instanceof OCSPResp) {
			isTrusted((OCSPResp) data);
		} else {
			if (logger.isDebugEnabled())
				logger.debug("No se pudo validar la confianza porque no se reconoce el tipo indicado: " + ((data!=null)?data.getClass():"Tipo nulo"));
			throw new UnknownTrustException();
		}
	}

}
