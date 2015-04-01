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
package es.mityc.firmaJava.ocsp;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPResp;

import es.mityc.firmaJava.ocsp.exception.OCSPException;
import es.mityc.firmaJava.ocsp.exception.OCSPSignatureException;
import es.mityc.javasign.certificate.IOCSPCertStatus;
import es.mityc.javasign.utils.Base64Coder;

/**
 * Clase encargada de almacenar la informacion de las validaciones OCSP
 * 
 */

public class RespuestaOCSP
{
	private static final String PROVEEDOR_SUN = "SUN";

	public enum ESTADOS_RESPUESTA { SUCCESFULL, MALFORMED_REQ, INTERNAL_ERROR, TRY_LATER, SIG_REQUIRED, UNAUTHORIZED }; // TODO: inyectar este valor en un campo interno
	
	private int 						nroRespuesta = ConstantesOCSP.INTERRUPTED; // Por defecto
	private String						mensajeRespuesta = ConstantesOCSP.MENSAJE_INTERRUMPIDO; // Por defecto
	private OCSPResp 					respuesta;
	private Date 						tiempoRespuesta;
	private IOCSPCertStatus.TYPE_RESPONDER	tipoResponder;
	private String						valorResponder;
	private Date						fechaRevocacion;
	private ArrayList<X509Certificate>	ocspSignerCerts;


	/**
	 * Constructor de la clase respuestaOCSP
	 * @param nroRespuesta tipo de respuesta recibida del servidor OCSP
	 * @param mensajeRespuesta mensaje que corresponde con el tipo de respuesta
	 */
	public RespuestaOCSP(int nroRespuesta, String mensajeRespuesta)
	{
		this.nroRespuesta 		=	nroRespuesta;
		this.mensajeRespuesta	=	mensajeRespuesta;
	}


	/**
	 * Constructor vacío de la clase respuestaOCSP
	 */
	public RespuestaOCSP()
	{
		//No hace nada
	}

	/**
	 * Obtiene el cuerpo de la respuesta del servidor OCSP
	 * @return cuerpo de la respuesta
	 */
	public byte[] getRespuestaEncoded()
	{
		if (respuesta != null)
			try {
				return respuesta.getEncoded();
			} catch (IOException ex) {
				return null;
			}
		else
			return null;
	}
	
	public OCSPResp getRespuesta() {
		return respuesta;
	}

	public X509Certificate[] getCertificates() throws OCSPException {
		X509Certificate[] certs = null;
    	byte[] resp = getRespuestaEncoded();
    	if (resp != null) {
    		try {
    			OCSPResp respuestaOCSP = new OCSPResp(resp);
    			BasicOCSPResp basicOcsp = (BasicOCSPResp)respuestaOCSP.getResponseObject();
    			if (basicOcsp != null)
    				certs = basicOcsp.getCerts(PROVEEDOR_SUN);
    		} catch (IOException ex) {
    			throw new OCSPException(ex);
    		} catch (NoSuchProviderException ex) {
    			throw new OCSPException(ex);
    		} catch (org.bouncycastle.ocsp.OCSPException ex) {
    			throw new OCSPException(ex);
    		}
    	}
    	return certs;
	}


	/**
	 * Establece el cuerpo de la respuesta del servidor OCSP
	 * @param respuesta cuerpo de la respuesta
	 */
	public void setRespuesta(OCSPResp respuesta)
	{
		this.respuesta = respuesta;
	}
	
	public void setRespuesta(byte[] data) {
		try {
			respuesta = new OCSPResp(data);
		} catch (IOException ex) {
			respuesta = null;
		}
	}
	
	/**
	 * Obtiene el mensaje de la respuesta del servidor OCSP
	 * @return mensaje de la respuesta
	 */
	public String getMensajeRespuesta()
	{
		return mensajeRespuesta;
	}

	/**
	 * Establece el mensaje de la respuesta del servidor OCSP
	 * @param mensajeRespuesta mensaje de la respuesta
	 */
	public void setMensajeRespuesta(String mensajeRespuesta)
	{
		this.mensajeRespuesta = mensajeRespuesta;
	}

	/**
	 * Obtiene el tipo de respuesta que ha devuelto el servidor OCSP
	 * @return tipo de respuesta
	 */
	public int getNroRespuesta()
	{
		return nroRespuesta;
	}

	/**
	 * Establece el tipo de respuesta que ha devuelto el servidor OCSP
	 * @param nroRespuesta tipo de respuesta
	 */
	public void setNroRespuesta(int nroRespuesta)
	{
		this.nroRespuesta = nroRespuesta;
	}

	/**
	 *
	 * @return
	 */
	public Date getTiempoRespuesta() {
		Date resp = null;
		if (tiempoRespuesta != null)
			resp = new Date(tiempoRespuesta.getTime());
		return resp;
	}

	/**
	 *
	 * @param tiempoRespuesta
	 */
	public void setTiempoRespuesta(Date tiempoRespuesta) {
		this.tiempoRespuesta = new Date(tiempoRespuesta.getTime());
	}



	public IOCSPCertStatus.TYPE_RESPONDER getTipoResponder() {
		return tipoResponder;
	}



	public void setResponder(ResponderID responder) {
        ASN1TaggedObject tagged = (ASN1TaggedObject)responder.toASN1Object();
		switch (tagged.getTagNo()) {
			case 1:
				valorResponder = X509Name.getInstance(tagged.getObject()).toString();
				X509Principal certX509Principal = new X509Principal(valorResponder);
				X500Principal cerX500Principal = new X500Principal(certX509Principal.getDEREncoded());
				valorResponder = cerX500Principal.getName();
				tipoResponder = IOCSPCertStatus.TYPE_RESPONDER.BY_NAME;
				break;
			case 2:
				ASN1OctetString octect = (ASN1OctetString)tagged.getObject();
				valorResponder = new String(Base64Coder.encode(octect.getOctets()));
				tipoResponder = IOCSPCertStatus.TYPE_RESPONDER.BY_KEY;
				break;
		}
	}



	public String getValorResponder() {
		return valorResponder;
	}
	
	/**
	 * Devuelve la fecha de revocacion (si ha sido establecida)
	 * @return
	 */
	public Date getFechaRevocacion() {
		return fechaRevocacion;
	}
	
	/**
	 * Establece la fecha de revocacion
	 * @param fechas
	 */
	public void setFechaRevocacion(Date fecha) {
		if (fecha != null)
			fechaRevocacion = new Date(fecha.getTime());
	}
	
	/**
	 * Establece los certificados del firmante de la respuesta OCSP
	 * @param cert
	 */
	public void setOCSPSigner(ArrayList<X509Certificate> certs) {
		this.ocspSignerCerts = certs;
	}
	
	/**
	 * Devuelve los certificados del firmante de la respuesta OCSP (si ha sido establecido)
	 * @return
	 */
	public ArrayList<X509Certificate> getOCSPSigner() {
		return this.ocspSignerCerts;
	}
	
	/**
	 * Comprueba que la respuesta OCSP está firmada por la clave privada asociada a la clave pública indicada
	 * 
	 * @param pk
	 * @throws OCSPException Cuando no hay respuesta para verificar o la verificacion indica que no es valida
	 */
	public void checkSign(PublicKey pk) throws OCSPException {
		if (respuesta == null)
			throw new OCSPException();
        try {
			BasicOCSPResp respuestaBasica = (BasicOCSPResp)respuesta.getResponseObject();
			if (!respuestaBasica.verify(pk, ConstantesOCSP.SUN_RSA_SIGN))
				throw new OCSPSignatureException();
		} catch (org.bouncycastle.ocsp.OCSPException ex) {
			throw new OCSPException(ex.getMessage(), ex);
		} catch (NoSuchProviderException ex) {
			throw new OCSPSignatureException(ex.getMessage(), ex);
		}
	}

}