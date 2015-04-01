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
package es.mityc.javasign.certificate;

import java.security.cert.X509Certificate;

/**
 * <p>Base abstracta con metodología común para las clases que recogen estados de certificados.</p>
 */
public abstract class AbstractCertStatus implements ICertStatus {

	/** Estado del certificado. */
	protected CERT_STATUS certStatus = CERT_STATUS.unknown;
	/** Si el certificado está revocado, información sobre la revocación. */
	protected RevokedInfo revokedInfo = null;
	/** Certificado sobre el que se realiza la consulta. */
	protected X509Certificate certificate = null;

	/**
	 * <p>Certificado consultado.</p>
	 * @return X509Certificate consultado
	 * @see es.mityc.javasign.certificate.ICertStatus#getCertificate()
	 */
	public X509Certificate getCertificate() {
		return certificate;
	}

	/**
	 * <p>Codificación binaria del estado del certificado.</p>
	 * <p>La forma binaria depende de la especificación del estado de certificado que se implementa.</p>
	 * @return byte[] con el contenido en binario del estado
	 * @see es.mityc.javasign.certificate.ICertStatus#getEncoded()
	 */
	public abstract byte[] getEncoded();

	/**
	 * <p>Información sobre la revocación del certificado (si el estado es revocado).</p>
	 * @return datos de revocación, <code>null</code> si no está revocado
	 * @see es.mityc.javasign.certificate.ICertStatus#getRevokedInfo()
	 */
	public RevokedInfo getRevokedInfo() {
		return (revokedInfo != null) ? (RevokedInfo) revokedInfo.clone() : null;
	}

	/**
	 * <p>Estado del certificado.</p>
	 * @return estado del certificado según el enumerado {@link es.mityc.javasign.certificate.ICertStatus.CERT_STATUS}
	 * @see es.mityc.javasign.certificate.ICertStatus#getStatus()
	 */
	public CERT_STATUS getStatus() {
		return certStatus;
	}
	
	/**
	 * <p>Establece el estado del certificado.</p>
	 * @param status Estado del certificado según el enumerado {@link es.mityc.javasign.certificate.ICertStatus.CERT_STATUS}
	 */
	protected void setCertStatus(final CERT_STATUS status) {
		this.certStatus = status;
	}
	
	/**
	 * <p>Establece información sobre el motivo de revocación del certificado.</p>
	 * @param ri Información de revocación
	 */
	protected void setRevokedInfo(final RevokedInfo ri) {
		this.revokedInfo = (RevokedInfo) ri.clone();
	}
	
	/**
	 * <p>Establece el certificado sobre el que se realiza la consulta de estado.</p>
	 * @param cert Certificado consultado
	 */
	protected void setCertificate(final X509Certificate cert) {
		this.certificate = cert;
	}

}
