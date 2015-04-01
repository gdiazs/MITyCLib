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
package es.mityc.javasign.certificate.ocsp;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.ocsp.ConstantesOCSP;
import es.mityc.firmaJava.ocsp.OCSPCliente;
import es.mityc.firmaJava.ocsp.RespuestaOCSP;
import es.mityc.firmaJava.ocsp.exception.OCSPClienteException;
import es.mityc.firmaJava.ocsp.exception.OCSPProxyException;
import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatusRecoverer;
import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.trust.UnknownTrustException;

/**
 * <p>Recupera el estado de un certificado mediante una consulta OCSP a un OCSP responder disponible por canal HTTP.</p>
 */
@SuppressWarnings("deprecation")
public class OCSPLiveConsultant implements ICertStatusRecoverer {
	
	/** Looger. */
	static Log logger = LogFactory.getLog(OCSPLiveConsultant.class);
	
	/** Internacionalizador. */
	private static final II18nManager i18n = I18nFactory.getI18nManager(ConstantsOCSP.LIB_NAME);

	/** Ruta del servidor HTTP OCSP al que se realiza la consulta. */
	private String servidorOCSP;
	/** Validador de confianza */
	private TrustAbstract validadorConfianza;
	/** Validador OCSP vía Http-GET. */
	private OCSPCliente ocspCliente = null;
	
	/**
	 * <p>Constructor.</p>
	 * @param hostOCSPResponder url del servidor OCSP responder al que envían las consultas
     * @param truster
     *            Validador de confianza
	 */
	public OCSPLiveConsultant(String hostOCSPResponder, TrustAbstract truster) {
		servidorOCSP = hostOCSPResponder;
		validadorConfianza = truster;
	}
	
	/**
	 * <p>No implementado.</p>
	 * @param certList no implementado 
	 * @return no implementado
	 * @throws CertStatusException no implementado
	 * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertStatus(java.util.List)
	 */
	public List<ICertStatus> getCertStatus(final List<X509Certificate> certList) throws CertStatusException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}
	
	/**
	 * <p>Realiza una consulta de estado de un certificado sobre el OCSP Responder configurado.</p>
	 * @param cert Certificado a consultar
	 * @return Estado del certificado indicado
	 * @throws CertStatusException Lanzada si sucede algún problema durante la consulta de estado del certificado
	 * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertStatus(java.security.cert.X509Certificate)
	 */
    public ICertStatus getCertStatus(final X509Certificate cert) throws CertStatusException {
		// Obtenemos la respuesta del servidor OCSP
		OCSPStatus bloque = null;
		RespuestaOCSP respuesta = null;
		try {
			ocspCliente = new OCSPCliente(servidorOCSP);

			// Construimos la cadena de certificacion del certificado
			X509Certificate issuerCertificate = null;
			try {
				CertPath certPath = validadorConfianza.getCertPath(cert);
				List<? extends Certificate> certificates = certPath.getCertificates();
				if (certificates.size() > 1) {
					issuerCertificate = (X509Certificate)certificates.get(1);
				} else {
					issuerCertificate = (X509Certificate)certificates.get(0);
				}
			} catch (UnknownTrustException ex) {
				logger.error(i18n.getLocalMessage(ConstantsOCSP.OCSP_LIST_ERROR_1, cert.getIssuerX500Principal()), ex);
				//throw new CertStatusException(ex.getMessage(), ex);
				issuerCertificate = cert;
			}
			
			respuesta = ocspCliente.validateCert(cert, issuerCertificate);
		} catch (OCSPClienteException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		} catch (OCSPProxyException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		}

		if (respuesta == null) {
			respuesta = new RespuestaOCSP(ConstantesOCSP.INTERRUPTED, ConstantesOCSP.MENSAJE_INTERRUMPIDO);
			respuesta.setTiempoRespuesta(new Date(System.currentTimeMillis()));
		}
		bloque = new OCSPStatus(respuesta, cert);
		return bloque;
	}

    /**
     * <p>
     * Recupera el estado de la cadena de certificación del certificado indicado.
     * </p>
     * 
     * @param cert
     *            Certificado que se consulta
     * @return Lista de estados de la cadena de certificación del certificado
     *         consultado. El primer elemento de la lista será el estado del
     *         propio certificado.
     * @throws CertStatusException
     *             Lanzada cuando no se puede recuperar el estado del
     *             certificado
     * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertChainStatus(java.util.List)
     */
    public List<ICertStatus> getCertChainStatus(X509Certificate cert) throws CertStatusException {
        // Obtenemos la respuesta del servidor OCSP
        List<ICertStatus> result = new ArrayList<ICertStatus>();
        try {
            ocspCliente = new OCSPCliente(servidorOCSP);

            // Construimos la cadena de certificacion del certificado
            CertPath certPath = validadorConfianza.getCertPath(cert);
            List<? extends Certificate> certificates = certPath.getCertificates();
            int certificatesSize = certificates.size();
            for (int i = 0; i < certificatesSize; i++) {
                X509Certificate certificateToValidate = (X509Certificate)certificates.get(i);
                X509Certificate issuerCertificate;
                //Si es el ultimo certificado estamos ante el certificado raiz en el que el emisor es él mismo
                if (i == certificatesSize - 1) {
                    issuerCertificate = (X509Certificate)certificates.get(i);
                } else {
                    issuerCertificate = (X509Certificate)certificates.get(i+1);
                }
                RespuestaOCSP respuesta = ocspCliente.validateCert(certificateToValidate, issuerCertificate);
                OCSPStatus bloque = new OCSPStatus(respuesta, certificateToValidate);
                result.add(bloque);
            }
            
        } catch (OCSPClienteException ex) {
            throw new CertStatusException(ex.getMessage(), ex);
        } catch (OCSPProxyException ex) {
            throw new CertStatusException(ex.getMessage(), ex);
        } catch (UnknownTrustException ex) {
            throw new CertStatusException(ex.getMessage(), ex);
        }

        return result;
    }

    /**
     * <p>Operación no soportada.</p>
     * @param cert no utilizado
     * @return no utilizado
     * @throws CertStatusException no utilizado
     * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertChainStatus(java.security.cert.X509Certificate)
     */
    public List<List<ICertStatus>> getCertChainStatus(List<X509Certificate> certs) throws CertStatusException {
        throw new UnsupportedOperationException("Not Supported Operation");
    }
    
    /**
     * <p>Abrota la petición actual, si existe.</p>
     */
    public synchronized void abort() {
    	if (ocspCliente != null)
    		ocspCliente.abort();
    }
    
    /**
     * <p<Establece el tiempo máximo de espera en milisegundos.</p>
     */
    public void setTimeOut(int timeOut) {
    	if (ocspCliente != null)
    		ocspCliente.setTimeOut(timeOut);
    }
}
