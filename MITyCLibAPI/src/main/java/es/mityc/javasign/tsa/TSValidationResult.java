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
package es.mityc.javasign.tsa;

import java.math.BigInteger;
import java.security.cert.CertPath;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/** 
 * <p>Estructura de datos para la validación de un sello de tiempo.</p>
 */
public class TSValidationResult {

	/** fecha del sello de tiempo en formato String. */
	private String formattedDate = null;
	/** Fecha del sello en formato Date. */
	private Date date = null;
	/** Emisor del sello. */
	private X500Principal issuer = null;
	/** Cadena de certificados firmantes del sello. */
	private CertPath cadena = null;
	/** Precisión del sello de tiempo en microsegundos. */
	private long timeAccurracy = 0;
	/** Valor del sello. */
	private BigInteger stamp = null;
	/** Nombre del algoritmo empleado en el sello de tiempo. */
	private String stampAlg = null;
	/** Valor del Digest obtenido. */
	private String signDigest = null;
	/** Valor de Digest calculado. */
	private String stampDigest = null;
	/** Token del sello. */ 
	private byte[] timeStampRawToken = null;
	
	/**
	 * <p>devuelve la fecha extraida del sello de tiempo.</p>
	 * @return Fecha extraía del sello, o <code>null</code> si no existe
	 */
	public String getFormattedDate() {
		return formattedDate;
	}

	/**
	 * <p>Almacena la fecha extraida del sello.</p> 
	 * @param fecha Fecha a almacenar
	 */
	public void setFormattedDate(final String formattedDate) {
		this.formattedDate = formattedDate;
	}

	/**
	 * <p>Devuelve la fecha almacenada en formato Date.</p>
	 * @return Fecha almacenada, o <code>null</code> si no existe
	 */
	public Date getDate() {
		return date;
	}

	/**
	 * <p>Almacena la fecha extraída del sello de tiempo en formato Date.</p>
	 * @param fechaDate Fecha a almacenar
	 */
	public void setDate(final Date date) {
		this.date = date;
	}

	/**
	 * <p>Devuelve el emisor X500 extraído del sello.</p>
	 * @return Valor almacenado del emisor del sello, o <code>null</code> si no existe
	 */
	public X500Principal getTimeStampIssuer() {
		return issuer;
	}

	/**
	 * <p>Almacena el emisor extraído del sello de tiempo.</p>
	 * @param emisor Emisor X500 del sello de tiempo
	 */
	public void setTimeStampIssuer(final X500Principal issuer) {
		this.issuer = issuer;
	}

	/**
	 * <p>Devuelve el valor de digest extraído del sello de tiempo.</p>
	 * @return El valor de digest almacenado, o <code>null</code> si no existe
	 */
	public String getSignDigest() {
		return signDigest;
	}

	/**
	 * <p>Almacena el valor de Digest extraído del sello de tiempo.</p>
	 * @param firmaDigest Valor de Digest extraído
	 */
	public void setSignDigest(final String signDigest) {
		this.signDigest = signDigest;
	}

	/**
	 * <p>Devuelve la precisión en microsegundos extraída del sello de tiempo.</p>
	 * @return Valor de la precisión almacenada
	 */
	public long getTimeAccurracy() {
		return timeAccurracy;
	}

	/**
	 * <p>Almacena la precisión en microsegundos extraída del sello de tiempo.</p>
	 * @param precisionLong Precisión extraida del sello de tiempo
	 */
	public void setTimeAccurracy(final long timeAccurracy) {
		this.timeAccurracy = timeAccurracy;
	}

	/**
	 * <p>Devuelve el sello de tiempo extraído en formato BigInteger.</p>
	 * @return Valor del sello, o <code>null</code> si no existe
	 */
	public BigInteger getStamp() {
		return stamp;
	}

	/**
	 * <p>Almacena el sello de tiempo en formato BigInteger.</p>
	 * @param sello Sello a almacenar
	 */
	public void setStamp(final BigInteger stamp) {
		this.stamp = stamp;
	}

	/**
	 * <p>Devuelve el nombre del algoritmo empleado en el sello de tiempo.</p>
	 * @return Nombre del algoritmo de Digest, o <code>null</code> si no existe
	 */
	public String getStampAlg() {
		return stampAlg;
	}

	/**
	 * <p>Almacena el nombre del algoritmo empleado en el sello de tiempo.</p>
	 * @param selloAlg Nombre del algoritmo de Digest
	 */
	public void setStampAlg(final String selloAlg) {
		this.stampAlg = selloAlg;
	}

	/**
	 * <p>Devuelve el valor de Digest extraído del sello de tiempo.</p>
	 * @return Valor de Digest, o <code>null</code> si no existe
	 */
	public String getStampDigest() {
		return stampDigest;
	}

	/**
	 * <p>Establece el valor de Digest extraído del sello de tiempo.<p>
	 * @param selloDigest Valor de Digest
	 */
	public void setStampDigest(final String stampDigest) {
		this.stampDigest = stampDigest;
	}

	/**
	 * <p>Devuelve el token del sello de tiempo en crudo.</p>
	 * @return Token en crudo
	 */
	public byte[] getTimeStampRawToken() {
		return timeStampRawToken;
	}

	/**
	 * <p>Almacena el token del sello de tiempo en crudo.</p>
	 * @param tst Token en crudo a almacenar
	 */
	public void setTimeStamRawToken(final byte[] timeStampRawToken) {
		this.timeStampRawToken = timeStampRawToken;
	}

	/**
	 * <p>Devuelve la cadena de certificados firmantes del sello de tiempo.</p>
	 * @return Cadena de certificados
	 */
	public CertPath getCadena() {
		return cadena;
	}

	/**
	 * <p>Almacena la cadena de certificación del sello de tiempo.</p>
	 * @param cadena 
	 */
	public void setCadena(CertPath cadena) {
		this.cadena = cadena;
	}
}
