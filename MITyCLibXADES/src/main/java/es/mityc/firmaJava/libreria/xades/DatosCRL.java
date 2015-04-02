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

import java.security.cert.X509CRL;
import java.util.Date;

import es.mityc.firmaJava.trust.ConfianzaEnum;

/**
 */

public class DatosCRL {
	
	private String issuer = null;
	private Date fechaEmision = null;
	private Date fechaCaducidad = null;
	private X509CRL x509CRL = null;
	private ConfianzaEnum esCertConfianza = ConfianzaEnum.NO_REVISADO;
	
	
	public DatosCRL() {}
	
	/**
	 * Almacena información referente a una lista de revocación de certificados
	 * 
	 * @param issuer  .- Emisor de la CRL
	 * @param fechaEmision .- La fecha de emisión de la lista
	 * @param fechaCaducidad .- La fecha de caducidad de la lista
	 * @param x509CRL .- La lista propiamente dicha
	 * @param esCertConfianza .- Booleano que indica si la CRL es considerada de confianza
	 */
	public DatosCRL(String issuer,
			Date fechaEmision,
			Date fechaCaducidad,
			X509CRL x509CRL,
			ConfianzaEnum esCertConfianza) {
		this.issuer = issuer;
		this.fechaEmision = fechaEmision;
		this.fechaCaducidad = fechaCaducidad;
		this.x509CRL = x509CRL;
		this.esCertConfianza = esCertConfianza;
	}

	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public Date getFechaEmision() {
		return fechaEmision;
	}
	public void setFechaEmision(Date fechaEmision) {
		this.fechaEmision = fechaEmision;
	}
	public Date getFechaCaducidad() {
		return fechaCaducidad;
	}
	public void setFechaCaducidad(Date fechaCaducidad) {
		this.fechaCaducidad = fechaCaducidad;
	}
	public X509CRL getX509CRL() {
		return x509CRL;
	}
	public void setX509CRL(X509CRL x509crl) {
		x509CRL = x509crl;
	}
	public ConfianzaEnum esCertConfianza() {
		return esCertConfianza;
	}
	public void setEsCertConfianza(ConfianzaEnum esCertConfianza) {
		this.esCertConfianza = esCertConfianza;
	}
}