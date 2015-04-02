/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES".
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
package es.mityc.firmaJava.libreria.xades;

import es.mityc.javasign.certificate.ICertStatus;

/**
 */

public class RespYCerts {
	
	private String x509CertFile = null;
	private ICertStatus certstatus = null;
	private String idCertificado = null;
	private String idRespStatus = null;
	private String fileName = null;

	
	public RespYCerts() {
		// No hace nada
	}
	
	public String getIdCertificado() {
		return idCertificado;
	}

	public void setIdCertificado(String idCertificado) {
		this.idCertificado = idCertificado;
	}

	public String getIdRespStatus() {
		return idRespStatus;
	}

	public void setIdRespStatus(String idRespStatus) {
		this.idRespStatus = idRespStatus;
	}

	
	public String getX509CertFile() {
		return x509CertFile;
	}

	public void setX509CertFile(String certFile) {
		x509CertFile = certFile;
	}


	public ICertStatus getCertstatus() {
		return certstatus;
	}

	public void setCertstatus(ICertStatus certstatus) {
		this.certstatus = certstatus;
	}
	
	public void setFilename(String filename) {
		this.fileName = filename;
	}
	
	public String getFilename() {
		return fileName;
	}
}