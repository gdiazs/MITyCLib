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

import java.security.cert.X509Certificate;
import java.util.Date;

import es.mityc.firmaJava.ocsp.ConstantesOCSP;
import es.mityc.firmaJava.ocsp.RespuestaOCSP;
import es.mityc.javasign.certificate.AbstractCertStatus;
import es.mityc.javasign.certificate.IOCSPCertStatus;
import es.mityc.javasign.certificate.RevokedInfo;

/**
 * <p>Información sobre esl estado de un certificado obtenido mediante una consulta OCSP.</p>
 */
public class OCSPStatus extends AbstractCertStatus implements IOCSPCertStatus {

	/** Contenido binario de la respuesta OCSP. */
	private byte[] respOCSP = null;
	/** Fecha de la respuesta OCSP. */
	private Date dateResponse = null;
	/** Identificador del OCSP responder. */
	private String responderID = null;
	/** Tipo del identificador del OCSP responder. */
	private TYPE_RESPONDER responderType;
	
	protected OCSPStatus(){
	    
	}
	
	/**
	 * <p>Constructor.</p>
	 * 
	 * @param resp Respuesta OCSP del estado del certificado
	 * @param cert Certificado sobre el que se realiza la consulta de estado
	 */
	public OCSPStatus(RespuestaOCSP resp, X509Certificate cert) {
		super();
		setRespOCSP(resp.getRespuestaEncoded());
		setRespondeDate(resp.getTiempoRespuesta());
		setResponder(resp.getValorResponder(), resp.getTipoResponder());
		if (resp.getNroRespuesta() == ConstantesOCSP.GOOD) {
			setCertStatus(CERT_STATUS.valid);
		} else if (resp.getNroRespuesta() == ConstantesOCSP.REVOKED) {
			setCertStatus(CERT_STATUS.revoked);
			// TODO: recuperar el motivo de revocación
			setRevokedInfo(new RevokedInfo(null, resp.getFechaRevocacion()));
		} else { 
			setCertStatus(CERT_STATUS.unknown);
		}
		setCertificate(cert);
	}
	
	/**
	 * <p>Establece el contenido binario de la respuesta OCSP.</p>
	 * @param binary byte[] con el contenido binario de la respuesta OCSP
	 */
	private void setRespOCSP(final byte[] binary) {
		respOCSP = (binary != null) ? (byte[]) binary.clone() : null;
	}
	
	/**
	 * <p>Establece los datos de identificación del OCSP responder. </p>
	 * @param id cadena identificativa
	 * @param tipoResponder tipo de identificador del OCSP responder
	 */
	private void setResponder(final String id, final IOCSPCertStatus.TYPE_RESPONDER tipoResponder) {
		this.responderID = id;
		responderType = tipoResponder;
	}
	
	/**
	 * <p>Establece la fecha de la respuesta de la consulta de estado.</p>
	 * @param date fecha de la respuesta
	 */
	private void setRespondeDate(final Date date) {
		if (date != null)
			dateResponse = (Date) date.clone();
	}

	
	/**
	 * <p>Devuelve la cadena identificadora del OCSP Responder que generó esta respuesta OCSP.</p>
	 * @return cadena identificadora
	 * @see es.mityc.javasign.certificate.IOCSPCertStatus#getResponderID()
	 */
	public String getResponderID() {
		return (responderID != null) ? responderID : null;
	}

	/**
	 * <p>Devuelve el tipo de identificador del OCSP Responder.</p>
	 * @return tipo de identificador según {@link TYPE_RESPONDER}
	 * @see es.mityc.javasign.certificate.IOCSPCertStatus#getResponderType()
	 */
	public TYPE_RESPONDER getResponderType() {
		return responderType;
	}

	/**
	 * <p>Devuelve la fecha de emisión de la respuesta OCSP.</p>
	 * @return fecha de la respuesta OCSP 
	 * @see es.mityc.javasign.certificate.IOCSPCertStatus#getResponseDate()
	 */
	public Date getResponseDate() {
		return (dateResponse != null) ? (Date) dateResponse.clone() : null;
	}

	/**
	 * <p>Devuelve la respuesta OCSP en formato binario.</p>
	 * @return byte[] con la respuesta según la RFC 2560
	 * @see es.mityc.javasign.certificate.ICertStatus#getEncoded()
	 */
	public byte[] getEncoded() {
		return respOCSP;
	}

}
